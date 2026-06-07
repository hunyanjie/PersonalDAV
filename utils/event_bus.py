import weakref
import logging
from typing import Any


class EventBus:
    _instance: "EventBus | None" = None
    _subscribers: dict[str, set[weakref.ReferenceType | weakref.WeakMethod]]  # type: ignore[type-arg]

    def __new__(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._subscribers = {}
        return cls._instance

    def subscribe(self, event_type: str, callback: Any) -> None:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = set()

        if hasattr(callback, '__self__') and hasattr(callback, '__func__'):
            ref: Any = weakref.WeakMethod(callback)
        else:
            ref = weakref.ref(callback)

        self._subscribers[event_type].add(ref)

    def publish(self, event_type: str, *args: Any, **kwargs: Any) -> None:
        if event_type in self._subscribers:
            dead_refs: set[Any] = set()
            for ref in list(self._subscribers[event_type]):
                callback = ref()
                if callback is not None:
                    try:
                        callback(*args, **kwargs)
                    except Exception as e:
                        logging.getLogger("PrivateDAV").error(f"EventBus 回调执行失败: {e}")
                else:
                    dead_refs.add(ref)
            self._subscribers[event_type] -= dead_refs

# 定义事件常量
EVENT_CONTACTS_CHANGED = "contacts_changed"
EVENT_EVENTS_CHANGED = "events_changed"
EVENT_SETTINGS_CHANGED = "settings_changed"
EVENT_SERVER_STATE_CHANGED = "server_state_changed"

# 全局单例
event_bus = EventBus()
