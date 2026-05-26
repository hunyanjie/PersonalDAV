import weakref
import logging

class EventBus:
    """全局事件总线 - 实现观察者模式 (Observer Pattern) - 支持弱引用"""
    _instance = None
    _subscribers = {}

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(EventBus, cls).__new__(cls)
        return cls._instance

    def subscribe(self, event_type, callback):
        """订阅事件 - 使用弱引用防止内存泄漏"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = weakref.WeakSet()
        
        # 如果是普通方法，WeakSet 会自动处理其生命周期
        try:
            self._subscribers[event_type].add(callback)
        except Exception as e:
            logging.getLogger("PrivateDAV").error(f"EventBus 订阅失败: {str(e)}")

    def publish(self, event_type, *args, **kwargs):
        """发布事件"""
        if event_type in self._subscribers:
            # WeakSet 迭代时会自动跳过已被销毁的对象
            for callback in list(self._subscribers[event_type]):
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logging.getLogger("PrivateDAV").error(f"EventBus 回调执行失败: {str(e)}")

# 定义事件常量
EVENT_CONTACTS_CHANGED = "contacts_changed"
EVENT_EVENTS_CHANGED = "events_changed"
EVENT_SETTINGS_CHANGED = "settings_changed"

# 全局单例
event_bus = EventBus()
