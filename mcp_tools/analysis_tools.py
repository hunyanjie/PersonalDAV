"""MCP tools: conflict detection and duplicate analysis."""

import difflib
from datetime import datetime, timedelta
from typing import Any

from mcp_tools._state import get_contact_svc, get_event_svc
from mcp_tools.helpers import safe_json
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="检测可能重复的联系人（基于姓名/邮箱/电话的模糊匹配）")
    def detect_contact_duplicates(threshold: float = 0.8) -> str:
        logger.info(f"MCP 调用: detect_contact_duplicates threshold={threshold}")
        try:
            svc = get_contact_svc()
            items = svc.get_list_data()
            pairs = []
            for i, row in enumerate(items):
                uid_i, name_i = row[0], str(row[1] or "")
                email_i = str(row[2] or "")
                phone_i = str(row[3] or "")
                for j in range(i + 1, len(items)):
                    uid_j, name_j = items[j][0], str(items[j][1] or "")
                    email_j = str(items[j][2] or "")
                    phone_j = str(items[j][3] or "")
                    if not name_i and not name_j:
                        continue
                    score = max(
                        difflib.SequenceMatcher(None, name_i, name_j).ratio() if name_i and name_j else 0,
                        difflib.SequenceMatcher(None, email_i, email_j).ratio() if email_i and email_j else 0,
                        difflib.SequenceMatcher(None, phone_i, phone_j).ratio() if phone_i and phone_j else 0,
                    )
                    if score >= threshold:
                        pairs.append({
                            "uid_a": uid_i, "name_a": name_i,
                            "uid_b": uid_j, "name_b": name_j,
                            "similarity": round(score, 4),
                        })
            logger.info(f"MCP 返回: detect_contact_duplicates -> {len(pairs)} 对潜在重复")
            return safe_json({"duplicates": pairs, "total_pairs": len(pairs)})
        except Exception as e:
            logger.exception("MCP 异常: detect_contact_duplicates")
            return safe_json({"error": str(e)})

    @mcp.tool(description="检测指定时间范围内的时间冲突（重叠事件）")
    def detect_event_conflicts(date_from: str = "", date_to: str = "") -> str:
        logger.info(f"MCP 调用: detect_event_conflicts date_from={date_from} date_to={date_to}")
        try:
            svc = get_event_svc()
            items = svc.get_list_data()
            if not date_to:
                date_to = (datetime.now() + timedelta(days=30)).isoformat()
            if not date_from:
                date_from = datetime.now().isoformat()

            events = []
            for row in items:
                uid, summary = row[0], row[1]
                start, end = row[2] if len(row) > 2 else "", row[3] if len(row) > 3 else ""
                if start and end and start >= date_from and end <= date_to:
                    events.append({"uid": uid, "summary": summary, "dtstart": start, "dtend": end})

            conflicts = []
            for i, a in enumerate(events):
                for j in range(i + 1, len(events)):
                    b = events[j]
                    if a["dtstart"] < b["dtend"] and a["dtend"] > b["dtstart"]:
                        conflicts.append({
                            "event_a": {"uid": a["uid"], "summary": a["summary"],
                                        "dtstart": a["dtstart"], "dtend": a["dtend"]},
                            "event_b": {"uid": b["uid"], "summary": b["summary"],
                                        "dtstart": b["dtstart"], "dtend": b["dtend"]},
                        })
            logger.info(f"MCP 返回: detect_event_conflicts -> {len(conflicts)} 对冲突")
            return safe_json({"conflicts": conflicts, "total_conflicts": len(conflicts),
                              "events_in_range": len(events)})
        except Exception as e:
            logger.exception("MCP 异常: detect_event_conflicts")
            return safe_json({"error": str(e)})

    @mcp.tool(description="检测未来 N 天内的日程冲突")
    def detect_upcoming_conflicts(days: int = 7) -> str:
        logger.info(f"MCP 调用: detect_upcoming_conflicts days={days}")
        try:
            now = datetime.now()
            date_from = now.isoformat()
            date_to = (now + timedelta(days=days)).isoformat()
            svc = get_event_svc()
            items = svc.get_list_data()

            events = []
            for row in items:
                uid, summary = row[0], row[1]
                start, end = row[2] if len(row) > 2 else "", row[3] if len(row) > 3 else ""
                if start and end and start >= date_from and end <= date_to:
                    events.append({"uid": uid, "summary": summary, "dtstart": start, "dtend": end})

            conflicts = []
            for i, a in enumerate(events):
                for j in range(i + 1, len(events)):
                    b = events[j]
                    if a["dtstart"] < b["dtend"] and a["dtend"] > b["dtstart"]:
                        conflicts.append({
                            "date_range": f"{a['dtstart'][:10]} ~ {a['dtend'][:10]}",
                            "event_a": {"uid": a["uid"], "summary": a["summary"],
                                        "dtstart": a["dtstart"], "dtend": a["dtend"]},
                            "event_b": {"uid": b["uid"], "summary": b["summary"],
                                        "dtstart": b["dtstart"], "dtend": b["dtend"]},
                        })
            logger.info(f"MCP 返回: detect_upcoming_conflicts -> {len(conflicts)} 对冲突")
            return safe_json({"conflicts": conflicts, "total_conflicts": len(conflicts),
                              "events_in_range": len(events), "days": days})
        except Exception as e:
            logger.exception("MCP 异常: detect_upcoming_conflicts")
            return safe_json({"error": str(e)})
