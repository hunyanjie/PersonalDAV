"""Embedding providers and unified search service for AI-enhanced search."""

import abc
import difflib
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

MODELS_DIR = "data/models"


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if not norm_a or not norm_b:
        return 0.0
    return dot / (norm_a * norm_b)


def list_available_models() -> list[str]:
    """Scan MODELS_DIR for directories containing .onnx files."""
    if not os.path.isdir(MODELS_DIR):
        return []
    results = []
    for entry in os.listdir(MODELS_DIR):
        full = os.path.join(MODELS_DIR, entry)
        if os.path.isdir(full) and any(f.endswith(".onnx") for f in os.listdir(full)):
            results.append(entry)
    return sorted(results)


class EmbeddingProvider(abc.ABC):
    """Abstract embedding provider."""

    @abc.abstractmethod
    def embed(self, text: str) -> list[float]:
        ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...

    @property
    def is_semantic(self) -> bool:
        return False


class KeywordProvider(EmbeddingProvider):
    """Built-in keyword / fuzzy-match provider. Zero extra dependencies."""

    @property
    def name(self) -> str:
        return "keyword"

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError("KeywordProvider does not produce vectors")


class ONNXProvider(EmbeddingProvider):
    """ONNX Runtime embedding provider. Requires onnxruntime + tokenizers."""

    def __init__(self, model_dir: str):
        self._model_dir = model_dir
        self._session = None
        self._tok = None

    def _load(self):
        if self._session is not None:
            return
        try:
            import onnxruntime
        except ImportError:
            raise RuntimeError("onnxruntime not installed")
        try:
            from tokenizers import Tokenizer
        except ImportError:
            raise RuntimeError("tokenizers not installed")

        onnx_path = None
        for f in os.listdir(self._model_dir):
            if f.endswith(".onnx"):
                onnx_path = os.path.join(self._model_dir, f)
                break
        if not onnx_path:
            raise FileNotFoundError(f"No .onnx file found in {self._model_dir}")

        tok_path = os.path.join(self._model_dir, "tokenizer.json")
        if not os.path.isfile(tok_path):
            raise FileNotFoundError(f"tokenizer.json not found in {self._model_dir}")

        self._tok = Tokenizer.from_file(tok_path)
        self._tok.enable_truncation(max_length=128)
        self._tok.enable_padding(pad_id=0, pad_token="[PAD]", length=128)
        self._session = onnxruntime.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])

    def embed(self, text: str) -> list[float]:
        self._load()
        encoded = self._tok.encode(text)
        input_ids = encoded.ids
        attention_mask = encoded.attention_mask
        import numpy as np
        ort_inputs = {
            "input_ids": np.array([input_ids], dtype=np.int64),
            "attention_mask": np.array([attention_mask], dtype=np.int64),
        }
        outputs = self._session.run(None, ort_inputs)
        return outputs[0].squeeze().tolist()

    @property
    def name(self) -> str:
        return f"onnx:{os.path.basename(self._model_dir)}"

    @property
    def is_semantic(self) -> bool:
        return True


class APIEmbeddingProvider(EmbeddingProvider):
    """Remote API embedding (Ollama / OpenAI compatible)."""

    def __init__(self, url: str, model: str = "", api_key: str = ""):
        self._url = url.rstrip("/")
        self._model = model
        self._api_key = api_key

    def embed(self, text: str) -> list[float]:
        import httpx
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        payload: dict[str, Any] = {"input": text}
        if self._model:
            payload["model"] = self._model
        resp = httpx.post(f"{self._url}/embeddings", json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        embeds = data.get("data", [])
        if embeds and isinstance(embeds, list):
            return embeds[0].get("embedding", [])
        return data.get("embedding", [])

    @property
    def name(self) -> str:
        return f"api:{self._model or self._url}"

    @property
    def is_semantic(self) -> bool:
        return True


class EmbeddingService:
    """Unified search service — singleton. Switches between providers transparently."""

    _instance: "EmbeddingService | None" = None

    def __new__(cls) -> "EmbeddingService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._provider: EmbeddingProvider = KeywordProvider()
            cls._instance._cache: dict[str, list[float]] = {}
        return cls._instance

    @property
    def provider(self) -> EmbeddingProvider:
        return self._provider

    @property
    def provider_name(self) -> str:
        return self._provider.name

    def configure_keyword(self):
        self._provider = KeywordProvider()
        self._cache.clear()

    def configure_onnx(self, model_dir: str) -> bool:
        try:
            prov = ONNXProvider(model_dir)
            prov.embed("warmup")
            self._provider = prov
            self._cache.clear()
            logger.info("ONNX embedding provider ready: %s", model_dir)
            return True
        except Exception as e:
            logger.warning("ONNX init failed: %s", e)
            return False

    def configure_api(self, url: str, model: str = "", api_key: str = "") -> bool:
        try:
            prov = APIEmbeddingProvider(url, model, api_key)
            prov.embed("warmup")
            self._provider = prov
            self._cache.clear()
            logger.info("API embedding provider ready: %s", url)
            return True
        except Exception as e:
            logger.warning("API provider init failed: %s", e)
            return False

    def _get_contact_text(self, contact: dict) -> str:
        parts = [contact.get("full_name", ""), contact.get("email", ""), contact.get("phone", "")]
        return " ".join(p for p in parts if p)

    def _get_event_text(self, event: dict) -> str:
        return event.get("summary", "")

    def _rank_candidates(self, query: str, candidates: list[dict], text_fn: callable, top_k: int) -> list[dict]:
        query_vec = self._provider.embed(query)
        scored: list[tuple[float, dict]] = []
        for c in candidates:
            uid = c.get("uid", "")
            text = text_fn(c)
            if uid in self._cache:
                vec = self._cache[uid]
            else:
                try:
                    vec = self._provider.embed(text)
                    self._cache[uid] = vec
                except Exception:
                    vec = []
            if vec:
                score = cosine_similarity(query_vec, vec)
                scored.append((score, c))
            else:
                scored.append((0.0, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k]]

    def _keyword_filter_and_rank(self, query: str, items: list[dict], text_fn: callable, top_k: int) -> list[dict]:
        query_lower = query.lower().strip()
        if not query_lower:
            return items[:top_k]

        scored: list[tuple[float, dict]] = []
        for c in items:
            text = str(text_fn(c)).lower()
            if query_lower in text:
                ratio = difflib.SequenceMatcher(None, query_lower, text).ratio()
                scored.append((ratio, c))
            else:
                for v in c.values():
                    if query_lower in str(v).lower():
                        scored.append((0.5, c))
                        break
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k]]

    def search_contacts(self, query: str, top_k: int = 10) -> list[dict]:
        from services.contact_service import ContactService
        svc = ContactService()
        all_items = svc.get_all_items()

        candidates = []
        for uid, _ in all_items:
            c = svc.repo.get_by_uid(uid)
            if c:
                candidates.append({
                    "uid": c.uid,
                    "full_name": c.full_name,
                    "email": c.email,
                    "phone": c.phone,
                    "groups": getattr(c, "groups", ""),
                    "created_at": c.created_at or "",
                    "updated_at": c.updated_at or "",
                })

        if self._provider.is_semantic:
            return self._rank_candidates(query, candidates, self._get_contact_text, top_k)
        return self._keyword_filter_and_rank(query, candidates, self._get_contact_text, top_k)

    def search_events(self, query: str, top_k: int = 10, date_from: str = "", date_to: str = "") -> list[dict]:
        from services.event_service import EventService
        svc = EventService()
        all_items = svc.get_all_items()

        candidates = []
        for uid, _ in all_items:
            e = svc.repo.get_by_uid(uid)
            if e:
                if date_from and e.dtstart < date_from:
                    continue
                if date_to and e.dtend > date_to:
                    continue
                candidates.append({
                    "uid": e.uid,
                    "summary": e.summary,
                    "dtstart": e.dtstart,
                    "dtend": e.dtend,
                    "created_at": e.created_at or "",
                    "updated_at": e.updated_at or "",
                })

        if self._provider.is_semantic:
            return self._rank_candidates(query, candidates, self._get_event_text, top_k)
        return self._keyword_filter_and_rank(query, candidates, self._get_event_text, top_k)

    def rebuild_index(self, progress_callback: callable = None):
        if not self._provider.is_semantic:
            return
        from services.contact_service import ContactService
        from services.event_service import EventService
        contacts = ContactService().get_all_items()
        events = EventService().get_all_items()
        total = len(contacts) + len(events)

        self._cache.clear()
        for idx, (uid, raw) in enumerate(contacts):
            c = ContactService().repo.get_by_uid(uid)
            if c:
                text = self._get_contact_text({"full_name": c.full_name, "email": c.email, "phone": c.phone})
                if text.strip():
                    self._cache[uid] = self._provider.embed(text)
            if progress_callback:
                progress_callback(idx + 1, total)

        offset = len(contacts)
        for idx, (uid, raw) in enumerate(events):
            e = EventService().repo.get_by_uid(uid)
            if e:
                text = self._get_event_text({"summary": e.summary})
                if text.strip():
                    self._cache[uid] = self._provider.embed(text)
            if progress_callback:
                progress_callback(offset + idx + 1, total)
