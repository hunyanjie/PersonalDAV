import weakref
import logging

class EventBus:
    """全局事件总线 - 实现观察者模式 (Observer Pattern) - 支持弱引用且兼容绑定方法"""
    _instance = None
    _subscribers = {}

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(EventBus, cls).__new__(cls)
        return cls._instance

    def subscribe(self, event_type, callback):
        """订阅事件 - 自动识别普通函数与绑定方法"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = set()
        
        # 针对绑定方法（如 self.update_status_bar）使用 WeakMethod
        if hasattr(callback, '__self__') and hasattr(callback, '__func__'):
            ref = weakref.WeakMethod(callback)
        else:
            ref = weakref.ref(callback)
            
        self._subscribers[event_type].add(ref)

    def publish(self, event_type, *args, **kwargs):
        """发布事件 - 自动清理已失效的引用"""
        if event_type in self._subscribers:
            dead_refs = set()
            # 复制一份以防迭代时修改
            for ref in list(self._subscribers[event_type]):
                callback = ref()
                if callback is not None:
                    try:
                        callback(*args, **kwargs)
                    except Exception as e:
                        logging.getLogger("PrivateDAV").error(f"EventBus 回调执行失败: {str(e)}")
                else:
                    dead_refs.add(ref)
            
            # 清理失效的弱引用
            self._subscribers[event_type] -= dead_refs

# 定义事件常量
EVENT_CONTACTS_CHANGED = "contacts_changed"
EVENT_EVENTS_CHANGED = "events_changed"
EVENT_SETTINGS_CHANGED = "settings_changed"
EVENT_SERVER_STATE_CHANGED = "server_state_changed"

# 全局单例
event_bus = EventBus()
