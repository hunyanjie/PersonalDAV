# PersonalDAV - 全能 DAV 服务 + MCP

PersonalDAV 是一个带图形界面和 Web 管理面板的全能 DAV 服务，集 CardDAV（联系人）、CalDAV（日历事件）和 WebDAV 于一体，支持通过 MCP（模型上下文协议）让 AI 直接操作您的数据。所有数据本地存储，无需订阅任何云服务。

> [!NOTE]
> 由于学习原因, 本项目的开发速度会有所缓慢。

> [!IMPORTANT]
> 使用前请阅读[免责声明](DISCLAIMER.md)。本软件按「原样」提供，作者不对数据丢失或安全问题承担责任。

## 功能特性

- 🌐 **Web 管理界面** — 打开浏览器就能管理所有数据！无需安装任何软件。支持离线访问、日程桌面通知、拖拽上传文件、导入 .vcf/.ics 联系人/日程、图片预览放大缩小（支持触摸拖拽和缩放）、农历显示、主题色自定义、侧栏收缩、骨架屏加载动画、列表 FLIP 动画（v3.2 新增，v3.3 大幅增强）
- 🧑 **联系人管理** — 创建、编辑、删除联系人，支持vCard格式，支持头像照片
- 📎 **事件附件** — 为日历事件添加文件或链接附件，支持 base64 内联存储
- 📅 **日历事件管理** — 创建、编辑、删除日历事件，支持iCalendar格式，支持重复事件
- 🔄 **CardDAV + CalDAV + WebDAV** — 通过HTTP提供标准DAV服务，支持手机/电脑客户端同步
- 📤 **导入/导出** — 支持从vCard(.vcf)/iCalendar(.ics)文件或URL导入，支持导出选中数据
- 🤖 **MCP 服务** — 支持 AI（opencode、Claude 等）直接通过 MCP 协议管理您的联系人和日历
- 🔍 **语义搜索** — 支持关键词搜索和可选的语义搜索（ONNX 本地模型 / Ollama / OpenAI API），在联系人/日历标签页可直接切换 AI 搜索
- 🛡️ **MCP 操作安全** — 危险操作需人工确认，支持三种安全模式（允许/确认/禁止）
- 🖥️ **无界面服务器模式** — 通过 `main.py --headless` 或 `python -m personaldavd` 运行，不打开图形界面也能提供服务
- 🌐 **REST API** — 通过 HTTP 接口管理联系人和日历事件，方便集成到其他程序
- 🔗 **远程连接** — GUI 可通过 `--remote` 参数连接到远程服务器，管理远端数据
- 🔒 **SSL/TLS 支持** — 一键生成自签名证书，HTTP + HTTPS 双端口同时运行，兼容苹果设备同步
- 🔒 **统一密码保护** — 一个密码同时保护 WebDAV 和 MCP 服务，支持 PBKDF2 安全加密
- 🗜️ **数据库压缩** — 删除数据后空闲空间不浪费，可在设置页手动压缩或启动时自动整理
- 🛡️ **IP 访问控制** — 白名单/黑名单/CIDR/通配符，支持本机免密码
- 🔑 **URL 鉴权** — 附件下载链接带防伪签名，防止盗链和滥用
- 🌐 **Referer 防盗链** — 只允许指定来源的请求访问，防止外部引用
- 📡 **远程鉴权** — 将请求转发到外部服务验证，可对接自定义认证系统
- 📋 **鉴权日志** — 登录成功/失败均有日志记录，可溯源
- 📂 **FTP / FTFS / SFTP 文件服务** — 一键启动文件传输服务器，支持端口和根目录配置
- 🌐 **SMB / CIFS 网络共享** — 连接远程 SMB 服务器，浏览目录、挂载共享
- 🌐 **WebDAV 文件服务 `/dav/`** — 通过 WebDAV 协议远程管理文件，支持 PROPFIND/GET/PUT/DELETE/MKCOL，新增多挂载点支持
- 🗂️ **远程文件浏览器** — 图形化浏览 FTP/FTPS/SFTP/SMB 远程文件，支持上传下载删除重命名
- 📁 **本地文件管理** — 桌面端新增文件管理标签页，双击打开文件，支持搜索过滤
- 📅 **日历双视图** — 月视图按月份查看 + 日程视图虚拟滚动，多日事件跨天显示，当前时间定位线，打开自动定位到今日，日期显示农历
- 🖥️ **友好的GUI** — 图形界面操作，支持拖拽导入，所有窗口居中显示
- 🎨 **主题自定义** — 浏览器界面支持 HSL 主题色自定义，可自由调色，跨设备同步
- 💾 **本地存储** — 使用SQLite存储数据，无需额外配置
- 🔍 **类型安全** — 新代码强制 mypy --strict，持续提升代码质量
- 🌐 **跨平台** — 支持Windows、macOS和Linux

## 安装与运行

### 前提条件

- Python 3.10+

### 安装步骤

1. 克隆仓库或下载源代码：
   ```bash
   git clone https://github.com/hunyanjie/PersonalDAV.git
   cd PersonalDAV
   ```

2. 安装依赖：
   ```bash
   pip install -e .
   ```

   如需开发（运行测试），额外安装：
   ```bash
   pip install -e ".[dev]"
   ```

3. 运行程序（图形界面）：
   ```bash
   python main.py
   ```

4. 无界面模式（服务器模式）：
   ```bash
   # 通过 GUI 入口（推荐 — 打包成 exe 后也适用）
   python main.py --headless --port 8000

   # 或直接启动 daemon
   python -m personaldavd --port 8000
   ```

   `--headless` 完整的参数列表：

   | 参数 | 默认值 | 说明 |
   |------|--------|------|
   | `--host` | 127.0.0.1 | 监听地址 |
   | `--port`, `-p` | 8000 | 监听端口 |
   | `--log-level` | INFO | 日志级别 (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
   | `--log-json` | — | JSON 结构化日志输出 |
   | `--db-path` | data/dav_data.db | 数据库路径 |
   | `--dav-root` | ./dav_root | WebDAV 根目录 |

5. 远程连接（GUI 连到远程服务器）：
   ```bash
   python main.py --remote --remote-url http://你的服务器地址:8000
   ```

### 运行测试

```bash
python tests/run_all.py
```

依次执行：pytest 单元测试（23 项）→ MCP 内部工具测试（32 个工具）→ MCP HTTP 端到端测试（走 SSE 协议）→ MCP 鉴权测试（401/403/200 + 日志落盘）。

## 使用指南

### 服务器管理

1. 在"服务器管理"标签页中，设置端口号（默认为8000）
2. 点击"启动服务器"按钮
3. 服务器启动后，您将看到各协议对应的配置地址
4. **Web 管理界面**：打开浏览器访问 `http://localhost:8000`，即可通过网页管理联系人、日历、文件和设置

### 联系人管理

1. 在"联系人"标签页中，您可以：
    - 添加、编辑、删除联系人
    - 导入/导出联系人
    - 查看联系人原始数据

### 日历事件管理

1. 在"日历事件"标签页中，您可以：
    - 添加、编辑、删除日历事件
    - 导入/导出日历事件
    - 查看事件原始数据

### 安全设置

1. 在"设置 → 安全设置"中：
    - 设置统一访问密码（PBKDF2 加密）
    - 复制 MCP 令牌供 AI 连接
    - 配置 IP 黑白名单
    - 开启/关闭本机免密码
    - 配置指定 IP 免密码访问
    - **URL 鉴权**：开启后附件下载链接自动添加防伪签名，防止链接被盗用。可在设置中调整签名有效期
    - **Referer 防盗链**：设置允许的 Referer 来源（如您的网站地址），不在列表的请求自动拒绝
    - **远程鉴权**：填入外部认证服务的地址，每次请求都会转发到该服务验证，支持自定义认证逻辑

### MCP 服务

1. 在"设置 → MCP 服务"中启用 MCP 服务
2. 在 opencode 或支持 MCP 的 AI 工具中配置：

    ```json
    {
      "mcp": {
        "personal-dav": {
          "type": "remote",
          "url": "http://127.0.0.1:8000/mcp/sse"
        }
      }
    }
    ```

3. 如果设置了密码，还需要添加 `Authorization: Bearer <令牌>`（令牌从安全设置页复制）

> [!NOTE]
> 如果使用无界面模式（`main.py --headless` / `python -m personaldavd`），MCP 服务随主服务器自动启用，无需额外配置。

### REST API + Web UI

服务器模式下可以直接在浏览器中管理所有数据（访问 `http://localhost:8000`），也可以通过 HTTP 接口调用：

| 接口 | 说明 |
|------|------|
| `GET /api/health` | 服务器健康检查 |
| `POST /api/auth/token` | 获取访问令牌 |
| `GET /api/contacts` / `POST /api/contacts` | 联系人列表 / 创建 |
| `GET /api/events` / `POST /api/events` | 事件列表 / 创建 |
| `GET /api/files` / `POST /api/files/upload` | 文件浏览 / 上传（v3.2） |
| `GET /api/settings` / `PUT /api/settings/:key` | 设置读取 / 修改（v3.2） |
| `GET /api/stats` | 服务器统计数据（v3.2） |
| `GET /api/auth/logs` | 鉴权日志查询（v3.2） |

详细文档访问服务器后打开 `http://localhost:8000/api/docs`。

## 客户端配置

> [!IMPORTANT]
> 如果设置了访问密码，客户端需要输入密码（用户名任意）。

### CardDAV 配置

- 服务器地址: `http://localhost:8000/contacts/`
- 用户名: (任意)
- 密码: (访问密码，如已设置)

### CalDAV 配置

- 服务器地址: `http://localhost:8000/events/`
- 用户名: (任意)
- 密码: (访问密码，如已设置)

## MCP 可用工具

MCP 服务提供 41 个工具供 AI 调用：

| 工具 | 说明 |
|------|------|
| `server_start` / `server_stop` / `server_status` | 管理 DAV 服务器启停和状态查询 |
| `list_contacts` / `get_contact` | 查看联系人列表和详情 |
| `create_contact` / `update_contact` / `delete_contact` | 联系人增删改 |
| `create_contact_v2` | 通过结构化参数（姓名、邮箱、电话）创建联系人，无需拼接 vCard |
| `list_events` / `get_event` | 查看事件列表和详情 |
| `create_event` / `update_event` / `delete_event` | 事件增删改 |
| `get_config` | 查询软件配置和统计数据 |
| `dav_health_check` | 验证 DAV 服务器是否正常工作（含 `/dav/` 端点） |
| `ftp_servers_start` / `ftp_servers_stop` / `ftp_servers_status` | 管理 FTP/SFTP/TFTP 文件服务器启停和状态 |
| `ftp_list_dir` / `ftp_download` / `ftp_upload` | 远程 FTP/SFTP 目录浏览、文件下载和上传 |
| `ftp_delete` / `ftp_rename` / `ftp_mkdir` / `ftp_rmdir` | 远程 FTP/SFTP 文件/目录删除、重命名、创建、移除 |
| `smb_servers_start` / `smb_servers_stop` / `smb_servers_status` | 管理 SMB/CIFS 文件共享服务启停和状态 |
| `smb_list_shares` / `smb_list_files` | 查看 SMB 服务器上的共享目录和文件列表 |
| `dav_list_files` / `dav_upload` / `dav_download` | WebDAV 文件浏览、上传、下载 |
| `dav_delete` / `dav_mkdir` | WebDAV 文件删除和目录创建 |
| `search_contacts(query, limit)` / `search_events(query, ...)` | **v3.1** 语义/关键词搜索联系人和事件 |
| `detect_contact_duplicates(threshold)` | **v3.1** 检测可能重复的联系人 |
| `detect_event_conflicts(date_from, date_to)` / `detect_upcoming_conflicts(days)` | **v3.1** 日程时间冲突检测 |

## 项目架构

```
PersonalDAV/
├── main.py                  # 入口（TkinterDnD 主窗口 / --headless 服务器）
├── config.py                # 软件元信息
├── personaldavd/            # 无界面服务器模式（v3.0 新增）
│   ├── __main__.py          # 命令行入口：python -m personaldavd
│   ├── daemon.py            # FastAPI 应用工厂
│   ├── dav.py               # CardDAV + CalDAV + WebDAV ASGI 路由
│   ├── api.py               # REST API 路由
│   ├── auth.py              # 统一鉴权中间件
│   ├── files.py             # 文件管理 REST API（v3.2 新增）
│   ├── mcp.py               # MCP 集成模块
│   ├── models.py            # Pydantic 数据模型
│   ├── config.py            # 守护进程配置
│   └── logging.py           # 结构化日志 + 实时日志队列
├── webui/                   # v3.2 Web 管理界面（Vue 3 + Vite）
│   ├── dist/                # SPA 构建产物
│   ├── public/
│   │   ├── manifest.json    # PWA 清单（v3.3）
│   │   └── sw.js            # 离线 Service Worker（v3.3）
│   ├── src/
│   │   ├── api.js           # REST API 客户端封装
│   │   ├── router/          # Hash 路由
│   │   ├── services/
│   │   │   └── reminder.js  # 日程桌面通知轮询（v3.3）
│   │   └── views/           # 登录/概览/联系人/日历/文件/设置
│   └── package.json
├── data/                    # 运行产物（自动创建）
│   ├── dav_data.db          # SQLite 数据库
│   ├── remote_connections.key # Fernet 加密密钥
│   ├── attachments/         # 附件独立文件存储
│   └── log/                 # 日志文件
├── mcp_tools/               # MCP 工具模块（41 个工具，分文件管理）
├── models/                  # 数据模型层（dataclass）
├── database/                # 数据访问层（SQLite + Repository）
│   └── repositories/        # 泛型 CRUD 仓储
├── services/                # 业务逻辑层
│   ├── base_service.py      # 泛型 Service 基类
│   ├── auth_service.py      # 统一鉴权（PBKDF2 + IP 访问控制）
│   ├── file_mount_service.py# 多挂载点管理服务（v3.2 新增）
│   ├── dav_client_service.py# WebDAV 客户端（远程挂载，v3.2 新增）
│   ├── mcp_server.py        # MCP SSE 服务器
│   ├── ftp_service.py       # FTP/FTPS/SFTP/TFTP 服务器
│   ├── sync_service.py      # Nextcloud 定时同步
│   └── ...
├── network/                 # 网络层
│   ├── dav_server.py        # CardDAV + CalDAV + WebDAV HTTP 服务
│   ├── dav_client.py        # WebDAV 客户端（远程导入）
│   └── webdav_helper.py     # XML 响应构建
├── ui/                      # 视图层（Tkinter）
│   ├── app.py               # 主窗口 / 菜单 / 事件总线
│   ├── tabs/                # 标签页（联系人/日历/服务器/远程/文件）
│   ├── dialogs/             # 对话框（设置/事件/联系人/向导/确认）
│   └── widgets/             # 自定义控件（Toast/右键菜单/工具提示）
├── utils/                   # 工具层
│   ├── validators.py        # 端口/IP/密码强度校验
│   ├── attachment_store.py  # 附件文件存储管理
│   ├── crypto.py            # Fernet 加密
│   └── ...
└── tests/                   # 测试（pytest + MCP 集成 + 鉴权测试）
```

```mermaid
graph TB
    subgraph WebUI["Web 管理界面 (Vue 3 SPA)"]
        direction LR
        WLogin["登录页"]
        WDash["概览面板"]
        WContacts["联系人管理"]
        WCal["日历管理"]
        WFiles["文件管理"]
        WSettings["设置面板"]
    end

    subgraph GUI["图形界面（Tkinter）"]
        direction LR
        Contacts["联系人标签页"]
        Calendar["日历标签页"]
        Server["服务器标签页"]
        Remote["远程文件标签页"]
        Files["文件管理标签页"]
        Settings["设置对话框"]
    end

    subgraph Daemon["服务器（FastAPI + Uvicorn）"]
        direction LR
        DAV["DAV 协议"]
        REST["REST API"]
        MCP["MCP 协议"]
        AUTH["统一鉴权"]
    end

    subgraph Service["业务逻辑层"]
        direction LR
        ContactSvc["ContactService"]
        EventSvc["EventService"]
        AuthSvc["AuthService"]
        MountSvc["FileMountService"]
        FTPSvc["FTPService"]
    end

    subgraph Data["数据层"]
        DB[("SQLite (WAL)")]
        FS[("文件系统<br/>attachments/")]
    end

    WebUI -->|HTTP| REST
    GUI -->|默认| Service
    GUI -->|--remote| REST
    Daemon --> Service
    Service --> Data
    REST -->|HTTP| AI["AI 工具<br/>opencode / Claude"]
    REST -->|HTTP| Client["DAV 客户端<br/>手机/电脑"]
    DAV -->|HTTP| Client
    MCP -->|HTTP SSE| AI
    FTP -->|TCP| FTPClient["FTP 客户端"]
```

## 技术栈

| 层面 | 技术 |
|------|------|
| GUI 框架 | Tkinter / ttk / tkinterdnd2 |
| 数据库 | SQLite (WAL 模式 + 线程安全) |
| 服务器框架 | FastAPI + Uvicorn（v3.0 统一 ASGI 运行时） |
| DAV 协议 | FastAPI / Starlette ASGI 路由 |
| REST API | FastAPI + Pydantic（自动生成 OpenAPI 文档） |
| MCP 服务 | FastMCP + Starlette（集成到主服务器） |
| 加密 | PBKDF2-HMAC-SHA256（密码）、Fernet/AES-128-CBC（远程连接密码） |
| 数据格式 | vCard 3.0 / iCalendar 2.0 |
| 时区 | pytz / tzlocal / Babel |
| 网络协议 | HTTP/WebDAV、FTP/FTPS、SFTP、TFTP、SMB/CIFS |
| 测试 | pytest + tracemalloc + 像素截图对比 |

## 注意事项

- 该服务仅设计用于本地网络或个人使用
- 开启密码后请妥善保管，密码丢失无法找回
- 请勿在公共网络环境中使用，建议配合 IP 白名单 + 强密码

## 贡献

欢迎贡献代码、报告问题或提出建议！

### 报告问题

- 搜索 [Issues](https://github.com/hunyanjie/PersonalDAV/issues) 确认是否已有相同报告
- 提供复现步骤、操作系统、Python 版本等信息
- 如有相关日志，一并附上

### 提交 Pull Request

1. Fork 仓库并创建特性分支
2. 确保代码风格一致（参考现有代码）
3. 运行测试确保不破坏现有功能：`python tests/run_all.py`
4. 提交 PR 时说明改动目的和实现方式

### 开发环境

```bash
pip install -e ".[dev]"
python tests/run_all.py   # pytest 23 项 + MCP 测试 + 鉴权测试
```

### 代码规范

- Python 3.10+，使用类型注解
- 新代码须通过 `mypy --strict` 检查
- 导入顺序：标准库 → 第三方 → 本地模块
- 类名 `PascalCase`，函数/变量 `snake_case`
- 提交消息格式：`类型(模块): 描述`（`feat` `fix` `refactor` `perf` `docs` `test` `chore`）

### 想提意见？

支持[提issue](https://github.com/hunyanjie/PersonalDAV/issues)。

## 免责声明

使用前请阅读完整的[免责声明](DISCLAIMER.md)。简言之：

- 本软件按「原样」提供，无任何明示或暗示保证
- 作者不对数据丢失、泄露或任何损害承担责任
- 用户应自行做好数据备份
- 不建议将本软件暴露到公网

## 许可证

本项目采用 **Apache License Version 2.0**。

### 为什么选择 Apache 2.0？

Apache 2.0 是**宽松许可证**，没有 copyleft 约束：

| 维度 | 说明 |
|------|------|
| ✅ **自由使用** | 可自由使用、修改、分发，无论个人还是商业 |
| ✅ **无需开源衍生代码** | 修改后不必公开源代码（与 GPL/MPL 不同） |
| ✅ **专利保护** | 包含明确的专利授权，贡献者自动授予专利许可 |
| ✅ **兼容性好** | 与 GPL v3 兼容，广泛用于开源生态 |
| ❌ **无 copyleft** | 修改者没有义务回馈改进到社区 |

### 对本项目而言

- **如果您在个人/公司项目中使用**：直接引用无需开源
- **如果您分发修改版本**：保留 Apache 2.0 声明即可，修改部分无需公开
- **专有代码可单独存在**：不受影响

完整许可证文本见 [LICENSE](LICENSE) 文件，或访问 [https://apache.org/licenses/LICENSE-2.0](https://apache.org/licenses/LICENSE-2.0)。

---

通过PersonalDAV，您可以完全掌控自己的联系人、日历和文件数据，无需依赖任何第三方服务。
