# PersonalDAV 技术文档

## 技术栈

| 层面 | 技术 | 用途 |
|------|------|------|
| 语言 | Python 3.10+ | 类型注解、dataclass、match 语句 |
| GUI | tkinter / ttk / tkinterdnd2 | 桌面界面、原生控件、文件拖放 |
| 日历控件 | tkcalendar (Calendar) | 日历月视图、日期选择 |
| 数据库 | SQLite3（内置） | 本地存储，WAL 模式，单文件 |
| iCalendar | vobject / python-dateutil | iCalendar 解析/生成 |
| vCard | vobject + 自研 RobustVCardParser | vCard 解析/生成（含 QP/Base64 回退） |
| 时区 | pytz / tzlocal / Babel | 时区计算、本地化名称 |
| 网络（DAV） | http.server（内置） | CardDAV/CalDAV HTTP 服务器 (v2.1) |
| FTP 服务 | pyftpdlib | FTP/FTPS 服务器 (v2.5) |
| SFTP 服务 | paramiko | SFTP 服务器 (v2.5) |
| TFTP 服务 | tftpy | TFTP 服务器 (v2.5) |
| FTP 客户端 | ftplib + paramiko | 远程 FTP/FTPS/SFTP 文件浏览 (v2.5) |
| SMB 客户端 | pysmb | SMB/CIFS 网络共享浏览 (v2.5) |
| WebDAV 客户端 | webdavclient3 | 远程 WebDAV 导入 (v2.5) |
| HTTP 请求 | requests | URL 导入 |
| 国际化 | locale / Babel | 系统语言检测、时区名称本地化 |

> v2.6 变动：移除 `lxml` 依赖，改用标准库 `xml.etree.ElementTree`。`pyftpdlib`、`paramiko`、`pysmb` 改为惰性导入（首次使用时才加载），未安装时功能不可用但程序不崩溃。

---

## 启动流程

程序启动过程（从双击到窗口出现）按顺序执行：

```
main()
  ├── argparse 解析命令行参数（--port / --db-path / --log-level）
  ├── logging.basicConfig 初始化日志系统
  ├── Database(db_path=...)  [仅当 --db-path 或 --data-dir 指定时]
  │     ├── WAL mode + _start_wal_checkpoint() (PASSIVE, 每60s)
  │     └── _vacuum_if_needed() 空闲页 > 50% 自动 VACUUM
  ├── _migrate_old_files() 旧版本文件迁移
  ├── TkinterDnD.Tk() 创建主窗口
  └── DAVServerApp(root)
        ├── SettingsService() 加载设置
        ├── ContactService() 联系人服务单例
        ├── EventService() 事件服务单例
        ├── LoggingManager.setup() 日志文件配置
        ├── create_widgets() 构建 UI（标签页 / 状态栏 / 菜单）
        ├── DragDropHandler.setup() 拖拽绑定
        ├── EventBus 订阅
        ├── TrayManager.start() [pystray 可用时]
        └── root.after_idle(_deferred_startup)
              ├── _show_setup_wizard() [首次启动时弹出]
              ├── _sync_mcp_server() [后台线程，不阻塞]
              ├── 自动启动 DAV 服务器 [按设置]
              ├── 自动检查更新 [后台线程]
              ├── SSL 证书自动续期
              └── _start_periodic_sync() [Nextcloud 同步]

root.mainloop()
```

### 设计要点

- **窗口优先**：`create_widgets()` 在 `__init__` 中尽早调用，确保主窗口在 `_deferred_startup` 执行前已经显示
- **`after_idle` 延迟初始化**：DAV 服务器、MCP 服务、更新检查等耗时操作放在主循环启动后的空闲时刻执行，不阻塞窗口渲染
- **惰性服务（v2.7）**：`MCPServer` 对象在控制面板开启 MCP 功能前不创建；`mcp_tools/_state.py` 中 `ContactService`、`EventService`、`FTPService` 通过惰性 getter 在首次调用时实例化
- **重型导入按需加载**：`Database`、`SettingsDialog`、`TrayManager` 等模块从文件顶部移到使用处导入，减少模块级的传递性导入开销
- **后台线程**：MCP 工具注册 + uvicorn 启动、更新检查、证书续期、定时同步均在后台线程执行，主线程只处理 GUI 事件

---

## 架构总览

```
PersonalDAV/
├── main.py                    # 入口：TkinterDnD 主窗口
├── config.py                  # 软件元信息（名称、版本、作者等）
├── data/                      # 运行产物（启动时自动创建）
│   ├── dav_data.db            # SQLite 数据库
│   ├── dav_data.db.bak        # 自动备份
│   ├── remote_connections.key # Fernet 加密密钥
│   └── log/
│       └── dav_server.log     # 日志文件（启用时）
├── mcp_tools/                 # MCP 工具模块（v2.6 拆分）
│   ├── _state.py              # 共享状态（服务实例惰性 getter，首次调用时创建）
│   ├── helpers.py             # JSON 序列化 / 摘要辅助函数
│   ├── server_tools.py        # DAV 服务器启停（start/stop/status）
│   ├── contact_tools.py       # 联系人 CRUD + create_contact_v2
│   ├── event_tools.py         # 日历事件 CRUD
│   ├── config_tools.py        # 系统配置 / 健康检查
│   ├── webdav_tools.py        # WebDAV 文件操作
│   ├── ftp_tools.py           # FTP/SFTP 服务器管理 + 远程文件操作
│   └── smb_tools.py           # SMB 共享浏览
├── models/                    # 数据模型层
│   ├── setting_defs.py        # SettingDef 声明式设置定义
│   ├── constants.py           # 共享映射常量（状态/透明度/提醒/频率/预设等）
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
│   ├── base_service.py        # BaseService 泛型服务基类（含 get_etag / get_all_items）
│   ├── contact_service.py     # ContactService 单例
│   ├── event_service.py       # EventService 单例
│   ├── settings_service.py    # SettingsService 单例
│   ├── auth_service.py        # AuthService 统一鉴权（密码/IP控制/日志）
│   ├── ftp_service.py         # FTPService 单例（FTP/FTPS/SFTP/TFTP 服务器）
│   ├── ftp_client_service.py  # FTP/FTPS/SFTP 客户端（stateless 方法）
│   ├── smb_service.py         # SMBService 单例（SMB 客户端）
│   └── mcp_server.py          # MCPServer（MCP SSE 协议服务器）
├── network/                   # 网络层
│   ├── dav_server.py          # DAVHandler（HTTP 服务器，CardDAV/CalDAV/WebDAV 端点）
│   ├── dav_client.py          # WebDAV 客户端导入
│   └── webdav_helper.py       # WebDAV XML 响应构建（multistatus/propfind/error）
├── utils/                     # 工具层
│   ├── event_bus.py           # EventBus 观察者模式
│   ├── timezone_helper.py     # TimezoneHelper 可定制时区格式化
│   ├── encoding_helper.py     # QP/Base64 编解码
│   ├── vcard_parser.py        # RobustVCardParser 回退解析（策略模式）
│   ├── window_utils.py        # center_window() 窗口居中工具
│   ├── validators.py          # 端口/IP/密码强度验证（v2.8）
│   ├── attachment_store.py    # 附件文件存储管理（v2.8）
│   └── logger.py              # 日志系统（RotatingFile + GUI 输出）
├── tests/                     # 单元测试
│   ├── test_config.py         # 配置常量验证
│   ├── test_base_service.py   # BaseService 核心方法测试
│   ├── test_fuzzing.py        # 325 个模糊变异子测试
│   ├── test_memory_leak.py    # 内存泄漏检测（tracemalloc + gc）
│   ├── test_ui_snapshot.py    # UI 快照截图对比测试
│   ├── test_mcp_auth_http.py  # MCP 鉴权 HTTP 测试
│   ├── _run_mcp_tools_check.py    # MCP 内部工具端到端测试
│   └── _run_mcp_http_check.py     # MCP HTTP/SSE 端到端测试
└── ui/                        # 视图层
    ├── app.py                 # DAVServerApp 主应用类
    ├── tabs/
    │   ├── base_tab.py        # BaseTreeTab 泛型 Treeview 基类（搜索/排序/多选/批量插入/加速滚动）
    │   ├── contacts_tab.py    # ContactsTab
    │   ├── calendar_tab.py    # CalendarTab（含月视图）
    │   ├── server_tab.py      # ServerTab（FTP/SFTP/TFTP/WebDAV 控制）
    │   └── remote_tab.py      # RemoteTab（多协议远程文件浏览器）
    ├── dialogs/
    │   ├── settings_dialog.py    # 声明式设置对话框
    │   ├── event_dialog.py       # 事件编辑对话框
    │   ├── contact_dialog.py     # 联系人编辑对话框
    │   ├── import_preview_dialog.py # 导入预览 + 对比对话框
    │   ├── text_import_dialog.py
    │   ├── webdav_import_dialog.py
    │   ├── confirm_dialog.py     # 标准化确认对话框（v2.8）
    │   └── setup_wizard.py       # 首次启动向导（v2.8）
    └── widgets/
        ├── enhanced_tooltip.py   # 悬浮提示框
        ├── right_click_menu.py   # 右键菜单（上下文感知）
        ├── progress_window.py    # 通用进度窗口
        ├── toast.py              # 非模态 Toast 通知（v2.8 类型化）
        └── treeview_scroller.py  # 拖拽自动加速滚动（compute_scroll_units）
```

> v2.6 数据目录重组：数据库、密钥、日志统一归入 `data/`，`main.py` 启动时自动从旧路径迁移文件。所有路径通过 `config.py` 的 `DEFAULT_DB_PATH` / `DEFAULT_LOG_FILE` 集中管理。

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

## 命令行参数

```bash
python main.py --port 8080 --db-path my_data.db --log-level DEBUG
```

| 参数 | 简写 | 说明 |
|------|------|------|
| `--port` | `-p` | WebDAV 服务器端口，覆盖设置中的默认端口 (v2.1) |
| `--db-path` | | 数据库文件路径，默认 `data/dav_data.db` (v2.1) |
| `--log-level` | | 日志级别：DEBUG / INFO / WARNING / ERROR / CRITICAL (v2.1) |

`--db-path` 通过提前初始化 `Database(db_path=...)` 单例实现，需在所有服务实例化之前调用。

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
settings (key TEXT PRIMARY KEY, value TEXT)          -- v2.0
contacts (selected, uid, full_name, email, phone,    -- v2.0
          vcard, id, created_at, updated_at)
events   (selected, uid, summary, dtstart, dtend,    -- v2.0
          ical, id, created_at, updated_at)
auth_logs (id INTEGER PRIMARY KEY, client_ip,         -- v2.2
           method, ...)
remote_connections (id INTEGER PRIMARY KEY            -- v2.5
                    AUTOINCREMENT, label TEXT, host TEXT,
                    port INTEGER, username TEXT,
                    password TEXT, protocol TEXT,
                    encoding TEXT)
```

- `selected` 是运行时列（UI 复选框），不参与 INSERT
- `created_at` / `updated_at` 由 Service 层在 `add_or_update` 时设置
- 数据库通过 `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE` 迁移兼容旧库

### 自动备份（v2.6）

```python
# database/db_manager.py
class Database:
    def __init__(self, db_path: str):
        db_path_obj = Path(db_path)
        backup_path = db_path_obj.with_suffix(".db.bak")
        if db_path_obj.exists():
            shutil.copy2(db_path_obj, backup_path)
```

每次 `Database.__init__()` 启动时自动复制 `dav_data.db` → `dav_data.db.bak`。

### 数据库压缩（v2.7）

```python
def vacuum_full(self) -> int | None:
    """完整 VACUUM 重写数据库，释放所有空闲空间。
    
    安全说明：SQLite VACUUM 创建临时文件 → 复制数据 → 原子替换原文件。
    若中途崩溃或断电，原文件不受影响。
    """
```

- **自动压缩（启动时）**：`_vacuum_if_needed()` 在空闲页超过总页数 50% 且多于 100 页时自动执行全量 `VACUUM`（v2.7 改用全量 VACUUM 替代原 incremental_vacuum，后者对分散空闲页无效）
- **手动压缩**：在设置 → 备份与恢复中点击「压缩数据库」按钮，后台线程执行，模态进度窗防止重复操作
- **防重入**：`Database._vacuum_in_progress` 类级别标志，`vacuum_full()` 自身不通过 `execute()` 方法（避免 `threading.Lock` 不可重入死锁），直接操作 `self.conn.cursor()`

---

## UI Treeview 基类（BaseTreeTab）

### 功能

- 搜索栏（实时过滤，子类实现 `apply_filter`）(v2.0)
- 全选/反选（单击第一列复选框列头）(v1.2)
- 拖拽多选 + 自动加速滚动（`B1-Motion` → 边缘 10% 区域触发 `after(30ms)` 循环，越靠近边缘越快，1~50 行/tick）(v2.8)
- 增量式复选框同步（`_sync_checkboxes(uids=None)`，传 UIDs 时只更新指定行，不传时全量遍历）(v2.8)
- `_uid_to_item` / `_item_to_uid` 字典映射，避免 `tree.item()` Tcl 往返 (v2.8)
- 三态排序 (v2.0)
- 右键菜单（通过 `RightClickMenu`）(v2.0)
- 全局 `Ctrl+A` / `Delete` 快捷键 (v2.0)

### 大批量数据处理

`BaseTreeTab` 不再使用虚拟滚动（v2.8 之前 `PAGE_SIZE=500` 的窗口方案），而是全量数据一次性插入 Treeview，通过以下手段保证性能：

| 手段 | 说明 |
|------|------|
| `BATCH_SIZE=200` 分批异步插入 | `_batch_insert()` 每批插入 200 行，用 `after(1)` 调度下一批，初始加载不卡 UI |
| `_uid_to_item` / `_item_to_uid` 映射 | 在 `_batch_insert` 时建立，`_rerender` 时清空。UID ↔ item_id O(1) 双向查找，替代 `tree.item()` Tcl 调用 |
| `tree.set(column, value)` 单列写入 | 更新复选框时只写 `'selected'` 列，替代 `tree.item(values)` 读写全部列，Tcl 调用减半 |
| 增量式 `_sync_checkboxes(uids)` | 点击时只更新 `old_sel ^ new_sel` 变化的 UIDs；拖拽时只更新 `union(old_range, new_range)` 范围内的行 |
| `_drag_lo` / `_drag_hi` 范围追踪 | 拖拽期间跟踪已滚过的最大/最小行索引，确保复选框正确勾选/取消 |

### 拖拽自动加速滚动 (v2.8)

`TreeviewScroller.compute_scroll_units()` 根据鼠标在 Treeview 中的相对位置计算滚动速度：

```
深度 = (阈值 - 相对距离) / 阈值      # 0~1，越靠近边缘越大
脉冲数 = max(1, int(深度 * MAX_SCROLL_UNITS=50))
```

`_on_drag` 根据返回值调度 `after(30ms)` 定时循环 `_auto_scroll_tick()`，手离边缘即 `_stop_auto_scroll()` 取消定时器。

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
| 导入方法 `_import_*` / `show_text_import` 抽到 BaseTreeTab | 消除 contacts_tab / calendar_tab 各 200+ 行重复代码 |
| event_dialog 常量全部抽离到 models/constants.py | 消除 settings_dialog 对 EventDialog 的导入依赖，SRP 更清晰 |
| ETag 通过 `hashlib.md5(raw)` 实时计算 | 无状态、零存储开销，内容变更 ETag 自然失效 |
| `Database.reset()` 类方法 | 仅在测试中重置单例，允许测试使用 `:memory:` 数据库 |
| 密码存储 PBKDF2-HMAC-SHA256 + 盐 | 纯 hashlib + secrets，零外部依赖 |
| MCP 令牌 `sha256("mcp:" + stored_hash)` 确定性派生 | 改密码自动刷新令牌，无需手动重置 opencode.json |
| IP 黑白名单白名单优先 + CIDR/通配符 | 非空时严格白名单模式，兼容子网和通配需求 |
| `ip_bypasses_auth()` 本机默认免密 + bypass_localhost 开关 | 开发调试体验友好，生产环境可关闭 |
| `log_auth()` 统一入口 | 集中记录鉴权事件，后续可扩展浏览器指纹等字段 |
| EnhancedTooltip.text 直接赋值可动态切换 | 无需销毁重建，适合状态驱动的提示场景 |
| vcard 序列化前关闭 `wacky_apple_photo_serialize = False` | 恢复 RFC 2426 规范的 75 字符行折叠，默认开启为兼容 Apple Address Book |
| `att.encoded = True` + `encoding_param='BASE64'` | 阻止 TextBehavior 对已 base64 的 ATTACH 值二次编码 |
| `_load_photo_from_vcard` 延迟到 `after_idle` 异步执行 | 避免大图同步处理阻塞主线程界面响应 |
| `show_raw` 优先使用 DB 缓存的 raw 数据而非 `serialize()` | 避免 vCard 带大 PHOTO/iCal 带大 ATTACH 时重序列化卡顿 |
| `_parse_server()` 自动补全协议和剥离 `user@` 前缀 | 用户可输入 `ftp://user@host`、`sftp://host`、`host` 等多种格式 |
| FTO/FTPS 编码选择（combo 列入 32 种编码） | 解决中文服务器文件名乱码问题 |
| `ftp_password` 独立存储且优先于 WebDAV 密码 | 允许 FTP 用户使用不同于 WebDAV 的密码 |
| FTPS 日志通过 `isinstance(handler, TLS_FTPHandler)` 标记 | 实现同端口同时支持 FTP 和 FTPS 的日志区分 |
| `remote_connections` 表持久化 FTP 连接 | 防止程序重启后连接信息丢失 |
| Canvas 滚动画布 + `itemconfig(inner_window, width=e.width)` | 确保滚动容器内框宽度与画布同步，避免水平填充异常 |
| Calendar 月视图通过 monkey-patch `_prev_month` 等 4 个方法同步下拉框 | 无需轮询，Calendar 内置导航点击后立即同步 |
| 多选下载单文件走 save 对话框、多文件走 save 目录 | 单文件给出默认文件名，多文件批量下载到文件夹 |
| WebDAV `/dav/` 使用 `xml.etree.ElementTree` 手动构建 XML | 零外部依赖，避免引入重量级 `wsgidav` |

---

---

## 导入预览系统

### 设计目的

文件/URL/剪贴板导入统一经过预览对话框，用户确认后再实际写入数据库。

导入流程方法 (`_import_file` / `_import_url` / `_import_clipboard` / `show_text_import` / `show_import_preview` / `_import_selected` / `_open_import_preview`) 均在 `BaseTreeTab` 中一次性实现，子类只需提供三个接口：

| 接口 | 用途 |
|------|------|
| `_import_add_item(raw, force, publish)` | 实际调用 `add_contact` / `add_event` |
| `_import_refresh_list()` | 导入完成后刷新列表 |
| `_parse_data_to_items(data)` | 解析原始数据为 item 字典列表 |

子类通过 `self._import_type = 'contacts' | 'events'` 区分导入类型。

### 流程

```
BaseTreeTab 共享方法:
_import_file / _import_url / _import_clipboard / show_text_import
  │
  ▼
_parse_data_to_items(data)  [子类实现]
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

## DAV 服务器（dav_server.py）

### 端点路由 (v2.1)

| 路径前缀 | 服务 | 资源类型 |
|----------|------|----------|
| `/contacts/` | `ContactService` | CardDAV (text/vcard) |
| `/events/` | `EventService` | CalDAV (text/calendar) |
| `/` | 静态 HTML | 信息页 |

### HTTP 方法状态

| 方法 | 功能 | 备注 |
|------|------|------|
| `GET` | 读取单个资源或集合 | 返回 `ETag` 头 |
| `HEAD` | 仅返回元数据 | 返回 `Content-Length` + `ETag` |
| `PUT` | 创建/更新资源 | 返回 `ETag` 头 |
| `POST` | 创建资源 | 返回 `ETag` 头 |
| `DELETE` | 删除资源 | — |
| `PROPFIND` | 属性查询（WebDAV） | 返回资源类型、ETag、子资源列表 |
| `OPTIONS` | 查询服务器能力 | 按路径返回 `addressbook` / `calendar-access` |
| `REPORT` | 批量查询（v2.6） | 处理 `addressbook-multiget` / `calendar-multiget` |
| `COPY` | 复制资源（v2.6） | 支持文件（`/dav/`）和资源（`/contacts/`、`/events/`） |
| `MOVE` | 移动资源（v2.6） | 同上 |

### PROPFIND (v2.1)

返回标准 WebDAV 多状态响应，包含：

- `<D:resourcetype>` — `<C:addressbook/>` 或 `<C:calendar/>`
- `<D:getetag>` — 每个资源的 MD5 ETag
- `<D:getcontenttype>` — MIME 类型
- `<D:getcontentlength>` — 大小
- `<C:getctag>`（v2.6） — 集合 CTag，基于所有子资源 ETag 的哈希值，提升 CalDAV 客户端同步效率

支持 `Depth: 0`（仅自身）和 `Depth: 1`（含子资源）。

### REPORT 请求示例（v2.6）

```xml
<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-multiget xmlns:C="urn:ietf:params:xml:ns:carddav">
  <A:prop xmlns:A="DAV:">
    <A:getetag/>
    <C:address-data/>
  </A:prop>
  <A:href>/contacts/uid-1.vcf</A:href>
  <A:href>/contacts/uid-2.vcf</A:href>
</C:addressbook-multiget>
```

### 鉴权

`_check_auth()` 在每个 `do_*` 方法开头调用，处理流程（按顺序）：

1. **IP 访问控制** — 调用 `AuthService().check_ip(client_ip)`，被拒绝时 `log_auth()` 记录并返回 403
2. **密码开关** — 未设密码直接放行
3. **免密码 IP** — 调用 `AuthService().ip_bypasses_auth(client_ip)`，命中则放行 + 记录 `"免密 IP"`
4. **Basic Auth 校验** — 解析 `Authorization` 头，密码错误/格式错误/缺失均返回 401 + `WWW-Authenticate` 头

每次鉴权结果（成功/失败/拒绝/免密）均通过 `log_auth()` 记录，含客户端 IP 和 User-Agent。

### ETag (v2.1)

通过 `BaseService.get_etag(uid)` 计算：

```python
def get_etag(self, uid: str) -> str | None:
    raw = self.get_by_uid(uid)
    if raw is None:
        return None
    return f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
```

在 `GET` / `HEAD` / `PUT` / `POST` 响应中返回 `ETag` 头，支持客户端条件请求。

---

## 统一鉴权系统（services/auth_service.py）

### 设计目的

统一密码管理，一个密码同时保护 WebDAV、MCP 等所有服务。密码通过 PBKDF2-HMAC-SHA256（600,000 轮）加盐哈希后存储。

### 存储 (v2.2)

| 设置键 | 格式 | 示例 |
|--------|------|------|
| `access_password_hash` | `salt$hash` | `a1b2c3...$e4f5g6...` |

空值 = 未设置密码（鉴权关闭）。

### MCP 令牌 (v2.2)

令牌通过 `sha256("mcp:" + stored_hash)` 派生，确定性生成。更改密码自动刷新令牌。

### IP 访问控制 (v2.2)

| 设置键 | 作用 | 规则 |
|--------|------|------|
| `ip_whitelist` | 白名单 | 非空时仅允许名单内 IP，其余 403 |
| `ip_blacklist` | 黑名单 | 白名单通过后再检查，命中则 403 |
| `bypass_localhost` | 本机免密开关 | `"True"`/`"False"`，默认开启 |
| `ip_bypass_auth` | 自定义免密码 IP | 这些 IP 访问时不需密码验证 |

IP 匹配支持三种格式：
- **精确 IP** — `192.168.1.1`
- **CIDR** — `192.168.1.0/24`
- **通配符** — `192.168.*`

### 鉴权日志 (v2.2)

所有鉴权事件通过 `AuthService.log_auth(success, client_ip, method, extra)` 统一记录：

| 参数 | 示例 | 说明 |
|------|------|------|
| `success` | `True` / `False` | 登录成功或失败 |
| `client_ip` | `192.168.1.100` | 客户端 IP，可溯源 |
| `method` | `"WebDAV"` / `"MCP"` | 协议标识 |
| `extra` | `"UA=Mozilla..."` 或 `"免密 IP"` | 附加信息 |

成功事件写 `logger.info()`，失败事件写 `logger.warning()`。

### 免密码 IP

`ip_bypasses_auth(client_ip)` 检测流程：
1. `bypass_localhost=True` 且为本机（`127.0.0.1` / `::1` / `localhost`）→ 免密
2. `ip_bypass_auth` 列表中有匹配 → 免密
3. 否则需要密码

WebDAV `_check_auth()` 和 MCP 中间件均在密码/令牌校验前调用此方法，命中则直接放行并记录 `"免密 IP"`。

### TOTP 双因素认证（v2.5，已移除）

TOTP 在 v2.5 开发中实现并随后移除。原因：设置对话框保存后重开时 UI 不刷新（`_on_totp_toggle` 在 `_totp_verified=True` 时直接 return，跳过了 `_update_totp_ui_state`/`_update_totp_display`），且保存时 `AuthService().is_enabled()` 条件不满足导致配置无法持久化。

移除范围：
- `auth_service.py`：全部 TOTP 方法 + `hmac`/`struct`/`time`/`base64` 导入
- `settings_dialog.py`：全部 TOTP UI（8 个方法）
- 迁移：`s.set_setting("totp_secret", "")`

### 协议适配表

| 服务 | 认证方式 | 凭证来源 |
|------|---------|----------|
| WebDAV (HTTP) | `Basic Auth` | 任意用户名 + 密码 |
| MCP (SSE) | `Bearer Token` | 从设置页复制 |

### 扩展指南

添加新服务时，调用 `AuthService().verify_password(password)` 或 `verify_mcp_token(token)` 即可。如需 IP 控制，在请求入口处依次调用 `check_ip(client_ip)` → `ip_bypasses_auth(client_ip)` → `verify_*()` → `log_auth()`。

### 远程连接密码加密（v2.6）

`utils/crypto.py` 使用 cryptography 库的 Fernet（AES-128-CBC）加密 `remote_connections` 表中的密码字段：

- 密钥文件 `remote_connections.key` 自动生成于 `data/` 目录
- 加密/解密在 `remote_tab.py` 的 INSERT / UPDATE / SELECT 操作中透明完成
- 数据库存储为 base64 密文，不暴露明文

### FTP/SFTP 密码验证统一（v2.6）

`AuthService.verify_ftp_password()` 同时处理两种协议栈：
- `pyftpdlib` → `AuthServiceAuthorizer`
- `paramiko` → `SFTPAuthInterface.check_auth_password`

消除重复的密码校验逻辑，统一走 PBKDF2 哈希验证。

### 代码安全清理（v2.6）

- **裸 `except:` 全面消除**：20 处替换为 `except Exception:`，避免 `KeyboardInterrupt` / `SystemExit` 被意外吞没
- **`SOFTWARE_NAME` 统一**：所有遗留的 `"PrivateDAV"` 字符串替换为 `config.SOFTWARE_NAME`

---

## MCP 服务器（services/mcp_server.py）

### 设计目的 (v2.2)

MCP（Model Context Protocol）服务器允许 AI 助手（opencode、Claude 等）直接调用 PersonalDAV 的内部服务层，无需模拟 HTTP 请求。集成到 GUI 程序中，以 SSE 协议在后台线程运行。

### 架构

```
AI / opencode
    │  MCP 协议 (SSE, http://127.0.0.1:8100/sse)
    ▼
MCPServer (FastMCP + Uvicorn)
    │  后台线程，非阻塞
    ▼
ContactService / EventService / SettingsService
    │  publish=False（避免从后台线程触发 tkinter 回调）
    ▼
Database 单例（threading.Lock 保护）
```

### 类方法

```python
class MCPServer:
    def start(self, host="127.0.0.1", port=8100) -> bool   # 启动 SSE 服务器
    def stop(self) -> None                                   # 停止服务器
    @property
    def is_running(self) -> bool                             # 查询运行状态
```

`start()` 在 daemon 线程中依次执行：工具注册 → `sse_app()` 构建 → `uvicorn.Server.run()`，调用后立即返回，不阻塞主线程。`stop()` 设置 `should_exit = True`。

### 暴露的工具（共 33 个）

#### DAV 核心工具（16 个）

| 工具 | 类别 | 说明 |
|------|------|------|
| `server_start(port)` | 服务端管理 | 后台启动 DAV 服务器 |
| `server_stop()` | 服务端管理 | 停止 DAV 服务器 |
| `server_status()` | 服务端管理 | 查询运行状态 + 端口 |
| `list_contacts()` | 联系人 | 列出所有联系人摘要 |
| `get_contact(uid)` | 联系人 | 获取联系人完整 vCard |
| `create_contact(vcard_data)` | 联系人 | 从 vCard 创建联系人 |
| `create_contact_v2(name, email, phone)` | 联系人 | 通过结构化参数创建联系人，无需手动拼接 vCard |
| `update_contact(uid, vcard_data)` | 联系人 | 强制覆盖更新联系人 |
| `delete_contact(uid)` | 联系人 | 删除联系人 |
| `list_events()` | 日历 | 列出所有事件摘要 |
| `get_event(uid)` | 日历 | 获取事件完整 iCalendar |
| `create_event(ical_data)` | 日历 | 从 iCal 创建事件 |
| `update_event(uid, ical_data)` | 日历 | 强制覆盖更新事件 |
| `delete_event(uid)` | 日历 | 删除事件 |
| `get_config()` | 系统 | 返回配置（名称/版本/数量等） |
| `dav_health_check(base_url)` | 系统 | OPTIONS + PROPFIND + GET 端点验证（含 `/dav/`） |

#### FTP/SFTP 服务器管理（3 个）(v2.5)

| 工具 | 说明 |
|------|------|
| `ftp_servers_start()` | 启动 FTP/FTPS/SFTP/TFTP 文件传输服务 |
| `ftp_servers_stop()` | 停止所有文件传输服务 |
| `ftp_servers_status()` | 查询文件服务运行状态 |

#### FTP/SFTP 文件操作（7 个）

| 工具 | 说明 |
|------|------|
| `ftp_list_dir(host, port, username, password, path, protocol, encoding)` | 浏览远程目录 |
| `ftp_download(host, ..., remote_path, local_path)` | 下载远程文件到本地 |
| `ftp_upload(host, ..., local_path, remote_path)` | 上传本地文件到远程 |
| `ftp_delete(host, ..., path)` | 删除远程文件 |
| `ftp_rename(host, ..., old_path, new_path)` | 重命名远程文件或目录 |
| `ftp_mkdir(host, ..., path)` | 创建远程目录 |
| `ftp_rmdir(host, ..., path)` | 删除远程空目录 |

#### SMB 浏览（2 个）

| 工具 | 说明 |
|------|------|
| `smb_list_shares(host, username, password)` | 列出 SMB 共享 |
| `smb_list_files(host, share, path, username, password)` | 列出 SMB 目录文件 |

#### WebDAV 文件操作（5 个）

| 工具 | 说明 |
|------|------|
| `dav_list_files(base_url)` | 列出 WebDAV 目录 |
| `dav_upload(base_url, local_path, remote_path)` | 上传文件到 WebDAV |
| `dav_download(base_url, remote_path, local_path)` | 从 WebDAV 下载文件 |
| `dav_delete(base_url, path)` | 删除 WebDAV 文件/目录 |
| `dav_mkdir(base_url, path)` | 创建 WebDAV 目录 |

所有写入操作使用 `publish=False`（不触发 tkinter 事件循环），GUI 通过标签切换自动刷新。

### 工具模块化（v2.6）

v2.6 将工具从 `services/mcp_server.py`（824 行）拆分为 7 个独立模块，入口仅保留注册与启动逻辑（120 行）：

```
mcp_tools/
├── __init__.py       # 导出 all_tools 列表
├── _state.py         # 惰性 getter：get_contact_svc / get_event_svc / get_ftp_svc
├── helpers.py        # serialize_model / make_summary
├── server_tools.py   # 3 个工具
├── contact_tools.py  # 6 个工具（含 create_contact_v2）
├── event_tools.py    # 5 个工具
├── config_tools.py   # 2 个工具
├── webdav_tools.py   # 5 个工具
├── ftp_tools.py      # 10 个工具
└── smb_tools.py      # 2 个工具
```

优势：职责清晰、可单独测试、无需启动完整 GUI。

### 启动优化（v2.7）

v2.7 进一步优化启动速度：

1. **工具注册延迟到 `start()` 时**：`MCPServer.__init__()` 不再调用 `_register_tools()`，仅在 `start()` 方法中注册。创建 MCPServer 对象几乎零成本。
2. **后台线程注册**：`start()` 将工具注册 + `sse_app()` 构建 + `uvicorn.Server.run()` 全部放入后台 `daemon` 线程执行，`start()` 瞬间返回，不阻塞主线程。
3. **惰性服务实例化**：`mcp_tools/_state.py` 的 `CONTACT_SVC` / `EVENT_SVC` / `FTP_SVC` 改为 `get_contact_svc()` / `get_event_svc()` / `get_ftp_svc()` 惰性 getter，首次调用时才创建单例。
4. **防重复注册**：`_tools_registered` 标记确保 `_register_tools()` 只执行一次。

### 鉴权中间件

MCP 服务器通过 `_AuthASGIMiddleware`（原生 ASGI 中间件，兼容 SSE 流式响应）拦截 `/sse` 和 `/messages/` 路径，处理流程：

1. **IP 访问控制** — `check_ip(client_ip)`，拒绝时返回 403 + 记录日志
2. **密码开关** — 未设密码直接放行
3. **免密码 IP** — `ip_bypasses_auth(client_ip)`，命中则放行 + 记录 `"免密 IP"`
4. **Bearer Token 校验** — 解析 `Authorization` 头，缺失返回 401，无效返回 401 + 分别记录失败日志
5. **成功** — 记录 `log_auth(True, ...)`

所有鉴权事件（成功/失败/拒绝/免密）统一通过 `AuthService.log_auth()` 写入日志。

### 集成方式（v2.7 惰性创建）

```python
# app.py — 自动启停（v2.7：MCPServer 惰性创建）
self.mcp_server = None
self._sync_mcp_server()           # 读取 mcp_enabled 设置决定启停
event_bus.subscribe(EVENT_SETTINGS_CHANGED, self._sync_mcp_server)

def _sync_mcp_server(self):
    enabled = ...
    if enabled:
        if self.mcp_server is None:
            from services.mcp_server import MCPServer
            self.mcp_server = MCPServer()  # 轻量：只创建 FastMCP，不注册工具
        if not self.mcp_server.is_running:
            self.mcp_server.start(...)     # 后台线程：注册 + SSE + uvicorn
    elif self.mcp_server is not None and self.mcp_server.is_running:
        self.mcp_server.stop()
```

用户在设置界面勾选「启用 MCP 服务」→ 保存后，`EVENT_SETTINGS_CHANGED` 被发布，`_sync_mcp_server()` 动态启动或停止后台服务器。启用前 MCPServer 对象不存在，零内存开销。

### 独立运行

```bash
python -m services.mcp_server        # 默认 8100 端口
python -m services.mcp_server --port 8100
```

### 配置 opencode

```json
{
  "mcp": {
    "personal-dav": {
      "type": "remote",
      "url": "http://127.0.0.1:8100/sse"
    }
  }
}
```

---

## 单元测试

运行方式：

```bash
pytest tests/ -v -q
```

### 测试结构（共 23 项，325 个子测试）

| 文件 | 测试内容 |
|------|----------|
| `test_config.py` | 验证配置常量（名称、版本、默认路径等）(v2.1) |
| `test_base_service.py` | 测试 `BaseService` 全部公有方法（CRUD、ETag、列表查询）(v2.1) |
| `test_fuzzing.py` | 模糊测试：65 种变异输入 × 5 解析入口（vobject vCard/iCal、手动解析、service 入口）= 325 子测试 (v2.5) |
| `test_memory_leak.py` | 重复创建/销毁 tkinter widget 验证无内存泄漏（tracemalloc + gc 对象追踪）(v2.5) |
| `test_ui_snapshot.py` | 像素截图对比 + GUI 控件结构验证；`SNAPSHOT_UPDATE=1` 更新参考图 (v2.5) |
| `_run_mcp_tools_check.py` | MCP 全部 33 个工具的内部端到端测试 (v2.2) |
| `_run_mcp_http_check.py` | MCP 全部工具 HTTP/SSE 端到端测试（无密码 + 有密码两轮，走真实 SSE 协议）(v2.2) |
| `test_mcp_auth_http.py` | MCP 鉴权中间件 HTTP 测试：401/403/200 状态码、黑白名单、免密 IP、日志落盘 (v2.3) |

### 运行全部测试

```bash
python tests/run_all.py
```

依次执行：pytest 单元测试 → MCP 内部工具检查 → MCP HTTP 工具检查 → MCP 鉴权测试。

### 测试隔离

- `Database.reset()` 在 `setUpClass` 中重置单例，使用 `:memory:` 数据库
- 每个 `setUp` 清空表数据，测试之间互不干扰
- 自定义 `_TestRepo` / `_Item` 避免对真实模型的依赖
- HTTP 测试使用独立端口（8101、8102），互不冲突

---

## 内存泄漏检测（memory_leak_detector.py）(v2.5)

`utils/memory_leak_detector.py` 提供两种互补的内存泄漏检测方法：

### tracemalloc 快照对比

```python
from utils.memory_leak_detector import MemoryLeakDetector

d = MemoryLeakDetector()
d.snapshot()                          # 基准快照
obj = create_some_widget()
obj.destroy()
d.snapshot()                          # 操作后快照
diff = d.compare()                    # 操作前后的差异
# diff 包含新增和释放的文件/行号/大小信息
```

### gc 对象追踪

```python
d.track(widget_cls)                   # 追踪特定 class 的存活实例
# 创建销毁后检查存活实例数
count_before = d.count_instances(widget_cls)
# assert_equal(count_after, count_before)
```

### 测试用法

```python
def test_label_no_leak(self):
    d = MemoryLeakDetector()
    d.track(ttk.Label)
    before = d.count_instances(ttk.Label)
    labels = [ttk.Label(self.root, text=f"L{i}") for i in range(10)]
    for lb in labels: lb.destroy()
    after = d.count_instances(ttk.Label)
    assert after == before, f"泄漏 {after - before} 个 Label"
```

---

## 悬浮提示系统（EnhancedTooltip）(v2.1)

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
| SettingsDialog | 复制令牌 | 未设密码: "请先设置密码以生成令牌" / 已设密码: "复制令牌到剪贴板"（动态切换） |

### 动态文本更新

`EnhancedTooltip.text` 属性可直接赋值，无需重建 tooltip 对象。`_refresh_auth_ui()` 中根据密码状态切换提示文本。

---

## 扩展指南

### 添加新设置

1. 在 `SIMPLE_SETTINGS` 列表末尾添加一行 `SettingDef`
2. 若需要在新分区（新的 notebook 标签页），在 `__init__` 中创建新 frame 并调用 `_build_simple(new_frame, "新分区名")`
3. 在读取处通过 `ServicesService().get_setting("键名", "默认值")` 获取

## FTP / FTPS / SFTP 文件服务 (v2.5)

`services/ftp_service.py`

### FTPService（单例）

| 方法 | 说明 |
|------|------|
| `start()` | 读取设置启动 FTP（pyftpdlib）、FTPS（TLS_FTPHandler）和 SFTP（paramiko）后台线程 |
| `stop()` | 关闭所有连接，停止线程（5 秒超时） |
| `is_running` | 是否正在运行 |

### 鉴权

`AuthServiceAuthorizer` 将 FTP 登录验证委托给 `AuthService.verify_password`，所有登录用户获得完全读写权限。

`SFTPAuthInterface` 在 paramiko 传输层实现密码认证，使用相同的 AuthService。

### 路径安全

`StubSFTPServer._resolve()` 验证所有路径在 `root` 之下，防止目录遍历攻击。

### FTPS（FTP+SSL）

使用 `TLS_FTPHandler`（pyftpdlib 内置），复用 DAV 服务器的 SSL 证书和密钥。在服务器标签页通过"启用 FTPS"复选框控制。

### 编码选择

FTP 控制 `ftp_encoding` 设置（默认为 `utf-8`），下拉框含 32 种编码。SFTP 始终使用 UTF-8。

### 独立 FTP 密码

`ftp_password` 设置覆盖 WebDAV 密码用于 FTP/SFTP 登录；为空时回退到直接使用密码哈希比较。

### 匿名登录

未设密码时 FTP 允许匿名登录，`force_password` 设置不影响 FTP 匿名访问。

---

## FTP / SFTP 客户端服务 (v2.5)

`services/ftp_client_service.py` — stateless 工具函数，每次调用创建独立连接。

### 支持的协议

| 协议 | 实现 | 端口默认值 |
|------|------|-----------|
| `FTP` | `ftplib.FTP` | 21 |
| `FTPS` | `ftplib.FTP_TLS` | 21 |
| `SFTP` | `paramiko.SFTPClient` | 22 |

### 所有方法接受 encoding 参数

| 方法 | 说明 |
|------|------|
| `list_dir(host, port, username, password, path, protocol, encoding)` | 列出目录 |
| `download(host, port, ..., remote_path, local_path)` | 下载文件 |
| `upload(host, port, ..., local_path, remote_path)` | 上传文件 |
| `delete(host, port, ..., path)` | 删除文件 |
| `rename(host, port, ..., old_path, new_path)` | 重命名文件或目录 |
| `mkdir(host, port, ..., path)` | 创建目录 |
| `rmdir(host, port, ..., path)` | 删除空目录 |

---

## SMB / CIFS 网络共享 (v2.5)

`services/smb_service.py` — 基于 pysmb 库

### SMBService（单例）

| 方法 | 说明 |
|------|------|
| `list_shares(server, username, password)` | 列出远程服务器上的共享 |
| `list_files(server, share, path, username, password)` | 列出共享目录中的文件 |
| `mount(server, share, mount_point, ...)` | 注册挂载映射（跟踪式，非系统挂载） |
| `unmount(mount_point)` | 取消挂载映射 |
| `get_mounted_shares()` | 返回当前所有挂载的共享 |

### RemoteTab（远程文件浏览器）(v2.5)

`ui/tabs/remote_tab.py` — 由原 `smb_tab.py` 重命名扩展而来，支持多协议（SMB / FTP / FTPS / SFTP）。

#### 连接管理

- 服务器地址格式：`protocol://user@host`（协议可选，默认 SMB）
- 账户格式：`user@host` 自动解析，PS：密码可选
- 连接存储：`remote_connections` 数据库表持久化，启动时自动加载
- 挂载树双击重连

#### 文件操作

- 上传、下载（单文件 save 对话框 / 多选 save 目录）、删除、重命名、新建文件夹
- 所有操作在后台线程执行，界面不卡死
- 操作期间禁用文件操作按钮

#### 右键菜单

- 文件树右键：上传到此目录（空区域）、下载/删除/重命名（选中项）
- 挂载树右键：连接/编辑/删除（多选批量删除）
- 菜单项状态自适应：重命名仅单选可用，下载仅文件可用，删除要求有选中

#### 表头排序

点击列标题切换升降序，默认排序：文件夹优先再按名称。`_parse_size()` 数值化文件大小列用于排序。

---

## WebDAV 辅助模块 (v2.5)

`network/webdav_helper.py` — 手动构建 WebDAV XML 响应，不依赖 `wsgidav`。

### 函数

| 函数 | 说明 |
|------|------|
| `propfind_xml(resource_type, etag, content_type, content_length, href, ...)` | 构建单个 PROPFIND 响应 XML |
| `multistatus_xml(responses)` | 包裹多状态 XML 响应 |
| `error_xml(namespace, message)` | 构建 DAV 错误响应 |

---

## 窗口居中工具 (v2.5)

`utils/window_utils.py`

```python
from utils.window_utils import center_window
center_window(window, width=600, height=400)
```

### 原理

在窗口 IDLE 就绪后（`after_idle`），获取屏幕宽高和窗口宽高，计算偏移量后设置 `geometry("+x+y")`。支持指定宽度/高度，不指定时使用窗口当前尺寸。

### 应用位置

已应用于 10+ 个窗口/对话框：设置、事件编辑、联系人编辑、关于、导入预览、文本导入、WebDAV 导入、证书引导、关闭确认、检查更新。

---

## 审计日志协议筛选 (v2.5)

`services/auth_service.py` — `get_auth_logs_filtered(protocol="")` 使用 SQL `LIKE` 过滤。

| 协议 | SQL 条件 |
|------|----------|
| WebDAV | `method LIKE '%WebDAV%'` |
| FTP | `method LIKE '%FTP%' AND method NOT LIKE '%FTPS%'` |
| FTPS | `method LIKE '%FTPS%'`（通过 `isinstance(handler, TLS_FTPHandler)` 标记） |
| SFTP | `method LIKE '%SFTP%'` |
| MCP | `method LIKE '%MCP%'` |

在设置对话框审计日志查看器中通过下拉框选择。

---

## Calendar 月视图 (v2.4)

`ui/tabs/calendar_tab.py` — CalendarTab 支持"议程"和"月视图"两种模式。

### 月视图组件

- **tkcalendar Calendar** 控件显示月份，带内置翻月/翻年按钮
- **年月下拉框**（`ttk.Combobox`）替代静态标签，支持年份（±50 年）和月份选择
- **选定日事件列表**（`tk.Listbox`）显示选中日期的事件
- **导航同步**：通过 monkey-patch Calendar 的 `_prev_month` / `_next_month` / `_prev_year` / `_next_year` 方法，确保下拉框与 Calendar 显示同步

### 关键方法

| 方法 | 说明 |
|------|------|
| `_refresh_month_view()` | 刷新日历事件圆点和选定日列表 |
| `_sync_month_combos()` | 从 Calendar._date 同步下拉框 |
| `_month_prev()` / `_month_next()` | 上月/下月 |
| `_month_today()` | 跳回今天 |
| `_month_combo_changed()` | 下拉框选择触发跳转 |
| `_month_on_select()` | 点击日期更新事件列表 |

### 搜索过滤

月视图下搜索框输入时，`apply_filter` 末尾自动调用 `_refresh_month_view()`，使日历事件圆点和选定日列表同步过滤。

---

## 多个表头排序 (v2.0)

`BaseTreeTab.sort_tree(col)` **三态排序**：

1. **首次点击** → 升序，表头显示 `列名 (↑升序)`
2. **再次点击同列** → 降序，表头显示 `列名 (↓降序)`
3. **第三次点击同列** → 取消排序，恢复默认顺序

**默认排序**：`DEFAULT_SORT_COL` 和 `DEFAULT_SORT_REV` 指定。远程文件表默认：文件夹优先再按名称。

**文件大小列**：远程文件通过 `_parse_size()` 将 `"1.2 MB"` 解析为字节数用于数值比较。

---

## 多选下载/删除 (v2.5)

### 下载

- **单文件** → `asksaveasfilename` 保存对话框，用户选择路径
- **多文件/目录** → `askdirectory` 选择目标目录，依次下载所有选中文件
- 线程中执行，完成后显示成功数量

### 删除

- 弹出确认对话框列出待删除文件（`"\n".join(paths)`）
- 确认后在后台线程逐条删除
- 完成后刷新文件列表

---

## Canvas 滚动容器 (v2.5)

`ui/tabs/server_tab.py` 使用 `Canvas` + `Scrollbar` 包裹所有服务器设置控件以防止内容溢出：

```python
canvas = tk.Canvas(self)
scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
inner = ttk.Frame(canvas)
canvas.create_window((0, 0), window=inner, anchor="nw")

# 内框宽度随画布同步扩展
inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.bind("<Configure>", lambda e: canvas.itemconfig(inner_window, width=e.width))
```

- `inner.bind("<Configure>")` 更新 `scrollregion`，确保滚动范围正确
- `canvas.bind("<Configure>")` 同步内框宽度，避免水平填充异常
- 运行中端口和 DAV 根路径控件通过 `state=tk.DISABLED` 防止修改

---

## mypy 类型覆盖 (v2.5)

`mypy.ini` — 分模块管理严格度：

- **新代码**（`services/ftp_service.py`、`services/smb_service.py`、`services/ftp_client_service.py`、`ui/tabs/remote_tab.py`、`network/webdav_helper.py`、`utils/window_utils.py`）强制 `strict = True`
- **旧代码**逐步补齐类型注解
- **第三方库**（pyftpdlib、paramiko、pysmb）跳过未安装的 stub

---

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
    except Exception: return datetime.min
```
