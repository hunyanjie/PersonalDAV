# PersonalDAV 技术文档

## 技术栈

| 层面 | 技术 | 用途 |
|------|------|------|
| 语言 | Python 3.10+ | 类型注解、dataclass、match 语句 |
| GUI | tkinter / ttk / tkinterdnd2 | 桌面界面、原生控件、文件拖放 |
| 日历控件 | tkcalendar (DateEntry) | 日期选择器 |
| 数据库 | SQLite3（内置） | 本地存储，WAL 模式，单文件 |
| iCalendar | vobject / python-dateutil | iCalendar 解析/生成 |
| vCard | vobject + 自研 RobustVCardParser | vCard 解析/生成（含 QP/Base64 回退） |
| 时区 | pytz / tzlocal / Babel | 时区计算、本地化名称 |
| 网络 | http.server（内置） | CardDAV/CalDAV HTTP 服务器 |
| WebDAV 客户端 | webdavclient3 | 远程 WebDAV 导入 |
| HTTP 请求 | requests | URL 导入 |
| 国际化 | locale / Babel | 系统语言检测、时区名称本地化 |

---

## 架构总览

```
PersonalDAV/
├── main.py                    # 入口：TkinterDnD 主窗口
├── config.py                  # 软件元信息（名称、版本、作者等）
├── models/                    # 数据模型层
│   ├── setting_defs.py        # SettingDef 声明式设置定义
│   ├── constants.py           # STANDARD_VCARD_FIELDS / STANDARD_ICAL_FIELDS
│   ├── contact.py             # ContactModel dataclass
│   └── event.py               # EventModel dataclass
├── database/                  # 数据访问层
│   ├── db_manager.py          # Database 单例（SQLite + WAL + 事务）
│   └── repositories/
│       ├── base.py            # BaseRepository[T] 泛型 CRUD
│       ├── contact_repository.py
│       ├── event_repository.py
│       └── settings_repository.py
├── services/                  # 业务逻辑层
│   ├── base_service.py        # BaseService 泛型服务基类
│   ├── contact_service.py     # ContactService 单例
│   ├── event_service.py       # EventService 单例
│   ├── settings_service.py    # SettingsService 单例
│   └── import_service.py      # 旧导入框架（QueuedImportManager，仅保留兼容）
├── network/                   # 网络层
│   ├── dav_server.py          # DAVHandler（HTTP 服务器，CardDAV/CalDAV 端点）
│   └── dav_client.py          # WebDAV 客户端导入
├── utils/                     # 工具层
│   ├── event_bus.py           # EventBus 观察者模式
│   ├── timezone_helper.py     # TimezoneHelper 可定制时区格式化
│   ├── encoding_helper.py     # QP/Base64 编解码
│   ├── vcard_parser.py        # RobustVCardParser 回退解析（策略模式）
│   └── logger.py              # 日志系统（RotatingFile + GUI 输出）
└── ui/                        # 视图层
    ├── app.py                 # DAVServerApp 主应用类
    ├── tabs/
    │   ├── base_tab.py        # BaseTreeTab 泛型 Treeview 基类（搜索/排序/多选）
    │   ├── contacts_tab.py    # ContactsTab
    │   ├── calendar_tab.py    # CalendarTab
    │   └── server_tab.py      # ServerTab
    ├── dialogs/
    │   ├── settings_dialog.py    # 声明式设置对话框
    │   ├── event_dialog.py       # 事件编辑对话框
    │   ├── contact_dialog.py     # 联系人编辑对话框
    │   ├── import_preview_dialog.py # 导入预览 + 对比对话框
    │   ├── text_import_dialog.py
    │   └── webdav_import_dialog.py
    └── widgets/
        ├── enhanced_tooltip.py   # 悬浮提示框
        ├── right_click_menu.py   # 右键菜单（上下文感知）
        ├── progress_window.py    # 通用进度窗口
        └── treeview_scroller.py  # 拖拽自动滚动
```

---

## 声明式设置系统（SettingDef）

### 设计目的

消除传统设置对话框的样板代码。新增一个设置项只需一行定义，UI 构建、加载、保存、重置由 4 个引擎方法自动处理。

### SettingDef 字段说明

```python
@dataclass
class SettingDef:
    key: str            # 数据库键名，同时也是动态属性的后缀（如 "default_port" → self.default_port_var）
    label: str          # UI 显示的标签文字
    widget_type: str    # 控件类型：check | entry | combo | spin | scale | sep
    section: str        # 所属分区（"服务器控制" / "基本设置"），匹配 notebook 标签页
    default: Any = ""           # 重置时的默认值（Python 值）
    db_default: str = ""        # 数据库中存储的默认字符串（__post_init__ 自动转为 str(default)）
    options: Optional[list] = None    # combo 的下拉选项
    width: Optional[int] = None       # entry/spin/combo 的宽度
    spin_from: Optional[int] = None   # spinbox 最小值
    spin_to: Optional[int] = None     # spinbox 最大值
    columnspan: int = 1               # grid 跨列数
    display_map: Optional[Dict[str, str]] = None  # {显示值: 数据库值} 映射
```

### 支持控件类型

| widget_type | 生成的控件 | 存储类型 |
|-------------|-----------|----------|
| `check` | `ttk.Checkbutton` → `tk.BooleanVar` | `"True"` / `"False"` |
| `entry` | `ttk.Entry` → `tk.StringVar` | 原始字符串 |
| `combo` | `ttk.Combobox(state="readonly")` → `tk.StringVar` | 通过 `display_map` 映射 |
| `spin` | `ttk.Spinbox` → `tk.StringVar` | 数字字符串 |
| `scale` | `ttk.Scale` + 数值标签 → `tk.IntVar` | 数字字符串 |
| `sep` | `ttk.Separator` | 无存储，仅分割线 |

### 添加新设置

在 `settings_dialog.py` 的 `SIMPLE_SETTINGS` 列表末尾添加一行即可：

```python
# widget_type 为 "combo"，带 display_map（显示中文、存英文）
SettingDef("start_time_snap", "新建日程默认开始时间:", "combo", "基本设置",
           default="当前时间", db_default="current",
           options=["当前时间", "5整数倍", "10整数倍", "15整数倍", "30整数倍"],
           display_map={"当前时间": "current", "5整数倍": "5", "10整数倍": "10",
                        "15整数倍": "15", "30整数倍": "30"}, width=12),

# widget_type 为 "check"（复选框）
SettingDef("auto_start_server", "启动时自动启动服务器", "check", "服务器控制",
           default=False, db_default="False"),

# widget_type 为 "entry"（文本输入框）
SettingDef("default_port", "默认端口号:", "entry", "服务器控制",
           default="8000", width=10),
```

### 读取设置的值

```python
# 方式一：通过 SettingsService
from services.settings_service import SettingsService
s = SettingsService()
val = s.get_setting("start_time_snap", "current")

# 方式二：直接在对话框中访问动态属性
self.start_time_snap_var.get()  # 显示值
# 如需数据库值：
display_map = {...}  # 从对应的 SettingDef 获取
rev_map = {v: k for k, v in display_map.items()}
db_val = rev_map.get(self.start_time_snap_var.get(), "current")
```

### 引擎方法

```python
_build_simple(parent, section, start_row=0)  # 构建 UI 控件
_load_simple()                                # 从 DB 加载值到控件
_save_simple()                                # 从控件保存值到 DB
_reset_simple()                               # 重置所有控件为默认值
```

---

## 时区格式化系统（TimezoneHelper）

### 设计目的

允许用户自定义时区下拉框的显示格式，通过占位符字符串自由组合。

### 占位符

| 占位符 | 示例输出 | 说明 |
|--------|---------|------|
| `{offset}` | `UTC+08:00` | 当前 UTC 偏移量 |
| `{city}` | `Shanghai` | 时区 ID 的最后一段 |
| `{tz_id}` | `Asia/Shanghai` | 标准 pytz 时区 ID |
| `{localized}` | `中国标准时间` | Babel 本地化名称 |
| `{local_tag}` | ` [本地]` | 本地时区时附加，否则空字符串 |

### 默认格式

```
{offset} - {city} ({tz_id}) {localized}{local_tag}
→ UTC+08:00 - Shanghai (Asia/Shanghai) 中国标准时间 [本地]
```

### 双向缓存映射

`TimezoneHelper` 使用两个类变量缓存实现可靠的 `tz_id ↔ display` 双向查找：

```python
_display_to_tz: dict = {}  # "UTC+08:00 - Shanghai (Asia/Shanghai) ..." → "Asia/Shanghai"
_tz_to_display: dict = {}  # "Asia/Shanghai" → "UTC+08:00 - Shanghai ..."
```

- `get_localized_timezones()` 构建缓存，遍历 `pytz.common_timezones`
- `get_timezone_display_name(tz_id)` 查 `_tz_to_display`，未命中则实时格式化
- `extract_tz_id(display)` 查 `_display_to_tz`，未命中则正则回退
- `set_format(fmt)` 清空缓存，下次访问自动重建

### 全局生命周期

```python
# app.py — 应用启动时从 DB 加载格式
fmt = settings_service.get_setting("timezone_format", "{offset} - {city} ({tz_id}) ...")
TimezoneHelper.set_format(fmt)

# settings_dialog.py — 保存/重置时更新
TimezoneHelper.set_format(self.tz_fmt_var.get())
```

---

## 默认持续时间系统

### 设计目的

用户可配置新建日程的默认结束时间偏移量。通过两个 Spinbox（小时 + 分钟）自由设置，右侧附带常用预设按钮。

### 实现方式

持续时间是唯一手动构建的设置项（不在 `SIMPLE_SETTINGS` 中），因为需要同行排列两个 Spinbox 和多个预设按钮。构建在 `_build_simple` 之后手动插入：

```python
# settings_dialog.py — create_calendar_settings
row = self._build_simple(b_t, "基本设置")

# 手动构建（小时 + 分钟 Spinbox + 预设按钮）
ttk.Label(b_t, text="默认持续时间:").grid(row=row, column=0, ...)
df = ttk.Frame(b_t); df.grid(row=row, column=1, ...)
self._dur_h_var = tk.StringVar(value="1")
self._dur_m_var = tk.StringVar(value="0")
ttk.Spinbox(df, textvariable=self._dur_h_var, from_=0, to=23, width=3).pack(...)
ttk.Label(df, text="小时").pack(...)
ttk.Spinbox(df, textvariable=self._dur_m_var, from_=0, to=59, width=3).pack(...)
ttk.Label(df, text="分钟").pack(...)
for label, h, m in [("30分", 0, 30), ("1小时", 1, 0), ("1h30m", 1, 30), ("2小时", 2, 0)]:
    ttk.Button(df, text=label, width=6,
               command=lambda h=h, m=m: (
                   self._dur_h_var.set(str(h)), self._dur_m_var.set(str(m))
               )).pack(side=tk.LEFT, padx=2)
```

### 存储方式

DB 中存储总分钟数（字符串），如 `"60"`、`"30"`、`"90"`、`"120"`。

```python
# 加载
total_min = int(s.get_setting("default_duration", "60"))
self._dur_h_var.set(str(total_min // 60))
self._dur_m_var.set(str(total_min % 60))

# 保存
total_min = int(self._dur_h_var.get() or "0") * 60 + int(self._dur_m_var.get() or "0")
s.set_setting("default_duration", str(total_min))
```

### 读取逻辑（event_dialog.py）

```python
def _get_default_duration_minutes(self):
    if not self.db:
        return 60
    mode = self.db.get_setting("default_duration", "60")
    if mode == "custom":  # 旧版兼容
        return int(self.db.get_setting("default_duration_custom", "45"))
    try:
        return int(mode)
    except:
        return 60
```

结束时间 = 吸附后的开始时间 + `_get_default_duration_minutes()` 分钟。

### 预设按钮

| 按钮 | 小时 | 分钟 |
|------|------|------|
| 30分 | 0 | 30 |
| 1小时 | 1 | 0 |
| 1h30m | 1 | 30 |
| 2小时 | 2 | 0 |

---

## 泛型仓储模式（BaseRepository[T]）

### 设计目的

消除 ContactRepository 和 EventRepository 中重复的 CRUD 代码。

```python
class BaseRepository(Generic[T]):
    def __init__(self, table, model_cls, columns, insert_columns):
        # 子类只需提供表名、模型类、列列表
        self.db = Database()
        ...

    def add_or_update(self, entity: T) -> bool    # INSERT OR REPLACE
    def get_by_uid(self, uid: str) -> Optional[T]  # 查询单条
    def get_all(self) -> List[T]                   # 查询全部
    def delete(self, uid: str) -> bool             # 删除
    def count(self) -> int                         # 计数
```

### 子类示例

```python
class ContactRepository(BaseRepository[ContactModel]):
    def __init__(self):
        columns = ['selected', 'uid', 'full_name', 'email', 'phone', 'vcard', 'id', 'created_at', 'updated_at']
        insert_columns = [c for c in columns if c != 'selected']
        super().__init__('contacts', ContactModel, columns, insert_columns)
```

---

## 泛型服务基类（BaseService）

### 设计目的

统一 ContactService 和 EventService 的查询/删除/列表获取逻辑。

```python
class BaseService:
    def __init__(self, repo, changed_event, raw_field, list_fields):
        # repo: BaseRepository 实例
        # changed_event: 数据变更时发布的事件名称
        # raw_field: 原始数据字段名（如 "vcard" / "ical"）
        # list_fields: 列表显示的字段名元组
        ...

    def get_by_uid(self, uid: str) -> str | None       # 获取原始数据
    def get_list_data(self) -> list[tuple]              # 获取列表数据
    def get_all_raw(self) -> list[str]                  # 获取全部原始数据
    def get_selected_raw(self, uids: list) -> list[str] # 获取选中项的原始数据
    def delete(self, uid: str) -> bool                  # 删除并发布事件
    def count(self) -> int                              # 计数
```

### 单例模式

```python
class ContactService(BaseService):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        super().__init__(
            repo=ContactRepository(),
            changed_event=EVENT_CONTACTS_CHANGED,
            raw_field='vcard',
            list_fields=('selected', 'uid', 'full_name', 'email', 'phone', 'created_at', 'updated_at')
        )
```

> **注意**：Python 在 `__new__` 返回实例后会自动调用 `__init__`，单例模式会导致 `__init__` 被重复调用。通过在 `BaseService.__init__` 中加入 `_bs_initialized` 守卫解决。

---

## 事件总线（EventBus）

### 设计目的

实现模块间解耦的发布-订阅通信。

```python
# 常量
EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED,
EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED

# 订阅
event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.on_contacts_changed)

# 发布
event_bus.publish(EVENT_CONTACTS_CHANGED)
```

使用 `WeakMethod` 避免循环引用导致的内存泄漏。

---

## 三态排序系统

`BaseTreeTab.sort_tree(col)` 实现：

1. **首次点击** → 升序，表头显示 `列名 (↑升序)`
2. **再次点击同列** → 降序，表头显示 `列名 (↓降序)`
3. **第三次点击同列** → 取消排序，恢复默认顺序（自然 DB 顺序或 `DEFAULT_SORT_COL`）

时间列（`start`、`end`、`created_at`、`updated_at`）使用 `datetime.fromisoformat()` 比较，其他列使用字符串比较。

排序状态在数据刷新后通过 `_after_refresh()` 自动恢复。

---

## RobustVCardParser（策略模式）

当 `vobject.readOne()` 因数据损坏（如换行丢失）抛出 `ParseError` 时，回退到手动解析：

```python
class DecodingStrategy(ABC):
    @abstractmethod
    def decode(self, raw: str) -> str

class QuotedPrintableStrategy(DecodingStrategy): ...
class Base64Strategy(DecodingStrategy): ...
class PlainStrategy(DecodingStrategy): ...
```

`edit_contact` 和 `add_contact` 均使用此回退机制。

---

## 数据库层

### 数据库初始化

- WAL 模式（读写不阻塞）
- 线程安全（`threading.Lock`）
- 事务上下文管理器：`with self.db.transaction() as cursor:`
- `query()` / `query_one()` / `execute()` 便捷方法

### 表结构

```sql
settings (key TEXT PRIMARY KEY, value TEXT)
contacts (selected, uid, full_name, email, phone, vcard, id, created_at, updated_at)
events   (selected, uid, summary, dtstart, dtend, ical, id, created_at, updated_at)
```

- `selected` 是运行时列（UI 复选框），不参与 INSERT
- `created_at` / `updated_at` 由 Service 层在 `add_or_update` 时设置
- 数据库通过 `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE` 迁移兼容旧库

---

## UI Treeview 基类（BaseTreeTab）

### 功能

- 搜索栏（实时过滤，子类实现 `apply_filter`）
- 全选/反选（单击第一列复选框列头）
- 拖拽多选（`B1-Motion` 事件）
- 三态排序
- 右键菜单（通过 `RightClickMenu`）
- 全局 `Ctrl+A` / `Delete` 快捷键

### 子类需覆盖

```python
COLUMNS = []          # 列名列表
HEADINGS = {}         # {列名: 显示标题}
DEFAULT_SORT_COL = '' # 默认排序列（空 = 自然顺序）

def apply_filter(self, query): ...   # 搜索过滤
def refresh_*(): ...                 # 数据刷新，末尾调用 self._after_refresh()
def get_column_width(self, col): ... # 自定义列宽
```

---

## 关键设计决策

| 决策 | 理由 |
|------|------|
| SQLite WAL 模式 | 读写不阻塞，适合桌面应用 |
| `INSERT OR REPLACE` 而非 `UPDATE` | 简化 upsert 逻辑，UID 唯一 |
| BaseRepository 泛型 + 列字符串 | 避免 ORM 依赖，保持轻量 |
| BaseService 单例 + `_bs_initialized` 守卫 | 解决 `__new__` + `__init__` 重复调用 |
| DAVHandler 类级属性注入 | `BaseHTTPRequestHandler.__init__` 签名固定，无法构造函数注入 |
| EventBus WeakMethod | 避免观察者-被观察者循环引用 |
| TimezoneHelper 类变量缓存 + `set_format` 清空 | 格式变更后自动重建，无需手动刷新 |
| 结束分钟 Combobox 保留 5 分钟步进 | 保持与开始分钟一致的用户体验 |
| `selected` 列运行时不入库 | 避免数据库冗余字段 |
| 设置使用 `display_map` 分离显示和存储 | UI 显示中文，DB 存英文，国际化友好 |
| 批量导入 `publish=False` + 最后一次性刷新 | 避免 N 次 event_bus 同步回调触发 N 次 `refresh_events` |
| `force=True` 参数覆盖内容相同的条目 | 满足用户 "覆盖已存在条目" 的主动选择 |
| ImportPreviewFrame 继承 BaseTreeTab 覆写 `_on_click` | 复用搜索/排序/复选框框架，只禁数据列勾选 |
| CompareDialog 双栏 + 下拉切换而不是 N 面板并列 | 处理 10+ 个重复时不炸屏 |
| 右键菜单切换 "覆盖" / "重置UID" | 让用户决定冲突条目是覆盖旧数据还是生成新 UID 共存 |
| EnhancedTooltip 无边框 Toplevel + Enter/Leave 事件 | 轻量悬浮提示，不依赖第三方库 |

---

---

## 导入预览系统

### 设计目的

文件/URL/剪贴板导入统一经过预览对话框，用户确认后再实际写入数据库。

### 流程

```
_import_file / _import_url / _import_clipboard / show_text_import
  │
  ▼
_parse_data_to_items(data)
  │  解析原始数据、提取 UID/title、查 DB 标记 is_new
  ▼
ImportPreviewDialog(items)
  │  ImportPreviewFrame（BaseTreeTab 子类）
  │  ✓ 复选框选择 | 右键切换覆盖/重置UID | 双击对比
  │  "选择推荐" / "覆盖已存在条目" / "全选" / "全不选"
  ▼
_import_selected(selected_items, source)
  │  ProgressWindow（进度条 + 详细日志）
  │  逐条调用 add_event/add_contact
  ▼
refresh_events() (仅一次)
```

### ImportPreviewFrame

继承 `BaseTreeTab`，覆写 `_on_click` 使数据列不改变复选框状态。提供：

| 方法 | 功能 |
|------|------|
| `_default_checked(it)` | 判断默认是否勾选：新条目 ✓，重复/已存在 ✗ |
| `_status_text(it)` | 显示 "新条目" / "已存在(覆盖)" / "重复(重置)" 等 |
| `selected_items()` | 返回当前勾选的 items |
| `select_recommended()` | 恢复推荐选择 |
| `_on_right_click()` | 弹出 "覆盖更新" / "重置UID" 右键菜单 |
| `_set_default_action(it)` | 根据冲突类型设置默认操作 |

### 重复 UID 冲突处理

两种冲突类型：

| 类型 | 标记 | 默认操作 |
|------|------|----------|
| 导入内同 UID（多个条目 ID 相同） | `has_dup=True`, `_dup_idx` | 第一个 `overwrite`，后续 `new_uid` |
| 与数据库已有条目 UID 相同 | `is_new=False` | `overwrite` |

用户可通过右键切换：
- **覆盖更新 (保留原UID)**: 调用 `add_event(raw, force=True)`, 覆盖数据库对应条目
- **重置UID (作为新条目)**: 生成新 UUID 替换 `UID:xxx`，作为全新条目导入

### CompareDialog

对比两个或更多同 UID 条目的差异：

- 左侧 Listbox：点击切换左侧版本
- 右侧双栏：两个可缩放文本面板 + 下拉选择版本 + ⇄ 交换按钮
- 颜色标记：`common` 灰色、`diff` 黄色背景、`unique` 蓝色背景、`struct` 灰色斜体
- 支持任意数量重复条目（通过双栏 + 下拉切换，而非 N 面板并列）

---

## 增强批量导入（add_event/add_contact 参数）

### `force` 参数

```python
def add_event(self, ical_data: str, force: bool = False, publish: bool = True)
def add_contact(self, vcard_data: str, force: bool = False, publish: bool = True)
```

| 参数 | 默认值 | 效果 |
|------|--------|------|
| `force=False` | 内容相同时返回 `"unchanged"`, 跳过写入 |
| `force=True` | 即使内容完全相同也标记为 `"updated"`, 覆盖写入 DB |
| `publish=True` | 写入后同步发布 `EVENTS_CHANGED` / `CONTACTS_CHANGED` |
| `publish=False` | 不发布事件, 适合批量导入（最后手动刷新一次） |

### 性能优化

批量导入时（`_import_selected`）：
1. `publish=False` 避免每次写入都触发 `refresh_events()`（全表查询 + tkinter 树重建）
2. 日志每 10 条批量 flush 到 tkinter 主线程；进度条逐条更新
3. 最后一次性调用 `self.refresh_events()`

---

## 悬浮提示系统（EnhancedTooltip）

### 设计目的

为表单字段提供鼠标悬停提示，说明字段用途、格式要求等。

### 使用方式

```python
from ui.widgets.enhanced_tooltip import EnhancedTooltip

EnhancedTooltip(widget, "提示文字",
    background='#ffffea',   # 可选：背景色
    font=(None, 10))        # 可选：字体
```

### 实现细节

- 绑定 `<Enter>` / `<Leave>` 事件
- `Toplevel(overrideredirect=True)` 无边框窗口
- 相对鼠标指针偏移（10px, 5px）
- 默认淡黄色背景 `#ffffea`

### 已应用位置

| 对话框 | 字段 | 提示内容 |
|--------|------|----------|
| EventDialog | 事件标题* | "必填。事件的简要标题" |
| EventDialog | 地点 | "事件发生的地点或会议室" |
| EventDialog | 描述 | "事件的详细描述或备注" |
| EventDialog | 事件状态 | "事件状态: 已确认/待定/已取消" |
| EventDialog | 日历版本 | "iCalendar 版本号，通常保持 2.0" |
| ContactDialog | 姓名* | "必填。联系人显示名称" |
| ContactDialog | 邮箱 | "多个邮箱请用分号(;)分隔" |
| ContactDialog | 电话 | "多个电话请用分号(;)分隔" |

---

## 扩展指南

### 添加新设置

1. 在 `SIMPLE_SETTINGS` 列表末尾添加一行 `SettingDef`
2. 若需要在新分区（新的 notebook 标签页），在 `__init__` 中创建新 frame 并调用 `_build_simple(new_frame, "新分区名")`
3. 在读取处通过 `ServicesService().get_setting("键名", "默认值")` 获取

### 添加新模型

1. 在 `models/` 下创建 dataclass
2. 在 `database/repositories/` 下创建继承 `BaseRepository[ModelType]` 的子类
3. 在 `services/` 下创建继承 `BaseService` 的单例子类
4. 在 `ui/tabs/` 或 `ui/dialogs/` 中创建对应的 UI
5. 在 `database/db_manager.py` 中 `create_tables()` 添加建表/迁移代码
6. 在 `network/dav_server.py` 中 DAVHandler 添加 HTTP 端点

### 添加新 tab

1. 创建 `ui/tabs/xxx_tab.py`，继承 `BaseTreeTab`
2. 实现 `COLUMNS`、`HEADINGS`、`apply_filter`、`refresh_*` 等方法
3. 在 `DAVServerApp.create_widgets()` 中添加到 notebook
4. 在 `on_tab_changed` 中处理刷新逻辑

### 排序系统扩展

如需对自定义时间列排序，在 `_sort_key` 中添加列名：
```python
if col in ('start', 'end', 'created_at', 'updated_at', '新时间列'):
    try: return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
    except: return datetime.min
```
