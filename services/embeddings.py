"""Embedding providers and unified search service for AI-enhanced search."""

import abc
import difflib
import logging
import os
from typing import Any
import math

logger = logging.getLogger(__name__)

MODELS_DIR = "data/models"


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if not norm_a or not norm_b:
        return 0.0
    return dot / (norm_a * norm_b)


def mean_pooling(token_embeds: "np.ndarray", attention_mask: "np.ndarray") -> "np.ndarray":
    import numpy as np
    mask = attention_mask[:, :, np.newaxis].astype(np.float32)
    sum_emb = np.sum(token_embeds * mask, axis=1)
    sum_mask = np.maximum(np.sum(mask, axis=1), 1e-9)
    return sum_emb / sum_mask


def l2_normalize(emb: "np.ndarray") -> "np.ndarray":
    import numpy as np
    norm = np.linalg.norm(emb, axis=1, keepdims=True)
    return emb / np.maximum(norm, 1e-9)


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

    def _encode(self, text: str) -> dict[str, "np.ndarray"]:
        encoded = self._tok.encode(text)
        import numpy as np
        ids = np.array([encoded.ids], dtype=np.int64)
        mask = np.array([encoded.attention_mask], dtype=np.int64)
        ort_inputs: dict[str, np.ndarray] = {
            "input_ids": ids,
            "attention_mask": mask,
        }
        for inp in self._session.get_inputs():
            if inp.name == "token_type_ids":
                ort_inputs[inp.name] = np.zeros_like(ids)
            elif inp.name not in ort_inputs:
                ort_inputs[inp.name] = np.zeros(
                    [ids.shape[0]] + list(inp.shape[1:]), dtype=np.int64)
        return ort_inputs

    def embed(self, text: str) -> list[float]:
        self._load()
        ort_inputs = self._encode(text)
        outputs = self._session.run(None, ort_inputs)
        return self._postprocess(outputs, ort_inputs["attention_mask"])

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        self._load()
        import numpy as np
        batch_size = 64
        results: list[list[float]] = []
        for i in range(0, len(texts), batch_size):
            chunk = texts[i:i + batch_size]
            ids_list, mask_list = [], []
            special: dict[str, list[np.ndarray]] = {}
            for t in chunk:
                ort_inputs = self._encode(t)
                ids_list.append(ort_inputs["input_ids"])
                mask_list.append(ort_inputs["attention_mask"])
                for name, val in ort_inputs.items():
                    if name not in ("input_ids", "attention_mask"):
                        special.setdefault(name, []).append(val)
            batch_ids = np.concatenate(ids_list, axis=0)
            batch_mask = np.concatenate(mask_list, axis=0)
            feed: dict[str, np.ndarray] = {"input_ids": batch_ids, "attention_mask": batch_mask}
            for name, vals in special.items():
                feed[name] = np.concatenate(vals, axis=0)
            outputs = self._session.run(None, feed)
            embs = self._postprocess(outputs, batch_mask, batch=True)
            results.extend(embs)
        return results

    def _postprocess(self, outputs: list, attention_mask: "np.ndarray", batch: bool = False
                      ) -> "list[list[float]] | list[float]":
        import numpy as np
        emb = outputs[0]
        if emb.ndim == 1:
            return emb.tolist()
        if emb.ndim == 3 and emb.shape[1] > 1:
            emb = mean_pooling(emb, attention_mask)
            emb = l2_normalize(emb)
        if emb.ndim == 2:
            if batch:
                return emb.tolist()
            return emb[0].tolist()
        result = emb.squeeze().tolist()
        if batch and isinstance(result[0], (list, np.ndarray)):
            return result
        if not batch:
            return result
        return [result]

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
        uncached: list[tuple[int, str, dict]] = []
        for idx, c in enumerate(candidates):
            uid = c.get("uid", "")
            if uid not in self._cache:
                uncached.append((idx, uid, c))
        if uncached and self._provider.is_semantic:
            texts = [text_fn(u[2]) for u in uncached]
            try:
                vecs = self._provider.embed_batch(texts)
                for (idx, uid, c), vec in zip(uncached, vecs):
                    self._cache[uid] = vec
            except Exception:
                for idx, uid, c in uncached:
                    try:
                        self._cache[uid] = self._provider.embed(text_fn(c))
                    except Exception:
                        self._cache[uid] = []

        scored: list[tuple[float, dict]] = []
        for c in candidates:
            uid = c.get("uid", "")
            vec = self._cache.get(uid, [])
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

        max_items = 2000 if self._provider.is_semantic else len(all_items)
        candidates = []
        for idx, (uid, _) in enumerate(all_items):
            if idx >= max_items:
                break
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

        max_items = 2000 if self._provider.is_semantic else len(all_items)
        candidates = []
        for idx, (uid, _) in enumerate(all_items):
            if idx >= max_items:
                break
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
