# PersonalDAV - 私人CardDAV/CalDAV服务 + MCP

PersonalDAV是一个带图形界面的私人CardDAV/CalDAV服务，允许您在自己的电脑上轻松管理联系人和日历事件。无需复杂的服务器配置，无需订阅云服务，只需运行此应用程序即可创建您个人的联系人日历同步服务。同时还支持通过 MCP（模型上下文协议）让 AI 直接操作您的数据。

## 功能特性

- 🧑 **联系人管理** — 创建、编辑、删除联系人，支持vCard格式
- 📅 **日历事件管理** — 创建、编辑、删除日历事件，支持iCalendar格式，支持重复事件
- 🔄 **CardDAV/CalDAV服务** — 通过HTTP提供标准DAV服务，支持手机/电脑客户端同步
- 📤 **导入/导出** — 支持从vCard(.vcf)/iCalendar(.ics)文件或URL导入，支持导出选中数据
- 🤖 **MCP 服务** — 支持 AI（opencode、Claude 等）直接通过 MCP 协议管理您的联系人和日历
- 🔒 **统一密码保护** — 一个密码同时保护 WebDAV 和 MCP 服务，支持 PBKDF2 安全加密
- 🛡️ **IP 访问控制** — 白名单/黑名单/CIDR/通配符，支持本机免密码
- 📋 **鉴权日志** — 登录成功/失败均有日志记录，可溯源
- 🖥️ **友好的GUI** — 图形界面操作，支持拖拽导入
- 💾 **本地存储** — 使用SQLite存储数据，无需额外配置
- 🌐 **跨平台** — 支持Windows、macOS和Linux

## 安装与运行

### 前提条件

- Python 3.10+
- 所需的Python库：请参考`requirements.txt`

### 安装步骤

1. 克隆仓库或下载源代码：
   ```bash
   git clone https://github.com/hunyanjie/PersonalDAV.git
   cd PersonalDAV
   ```

2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

3. 运行程序：
   ```bash
   python main.py
   ```

### 运行测试

```bash
python tests/run_all.py
```

依次执行：pytest 单元测试（13 项）→ MCP 内部工具测试（16 个工具）→ MCP HTTP 端到端测试（走 SSE 协议）→ MCP 鉴权测试（401/403/200 + 日志落盘）。

## 使用指南

### 服务器管理

1. 在"服务器管理"标签页中，设置端口号（默认为8000）
2. 点击"启动服务器"按钮
3. 服务器启动后，您将看到CardDAV和CalDAV的配置信息

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

### MCP 服务

1. 在"设置 → MCP 服务"中启用 MCP 服务
2. 在 opencode 或支持 MCP 的 AI 工具中配置：

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

3. 如果设置了密码，还需要添加 `Authorization: Bearer <令牌>`（令牌从安全设置页复制）

## 客户端配置

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

MCP 服务提供 16 个工具供 AI 调用：

| 工具 | 说明 |
|------|------|
| `server_start` / `stop` / `status` | 管理 DAV 服务器启停和状态查询 |
| `list_contacts` / `get_contact` | 查看联系人列表和详情 |
| `create_contact` / `update_contact` / `delete_contact` | 联系人增删改 |
| `list_events` / `get_event` | 查看事件列表和详情 |
| `create_event` / `update_event` / `delete_event` | 事件增删改 |
| `get_config` | 查询软件配置和统计数据 |
| `dav_health_check` | 验证 DAV 服务器是否正常工作 |

## 技术栈

- **GUI框架**: Tkinter / ttk / tkinterdnd2
- **数据格式**: vCard (vcf), iCalendar (ics)
- **数据库**: SQLite (WAL模式)
- **HTTP服务器**: Python内置HTTPServer
- **MCP服务器**: FastMCP + Uvicorn (SSE协议)
- **主要依赖**:
    - `vobject` — vCard和iCalendar解析
    - `python-dateutil` — 日期解析
    - `pytz` / `tzlocal` — 时区处理
    - `babel` — 日期和时间的国际化
    - `requests` / `httpx` — HTTP请求
    - `tkcalendar` — 日历选择控件
    - `mcp` — MCP 协议库

## 注意事项

- 该服务仅设计用于本地网络或个人使用
- 开启密码后请妥善保管，密码丢失无法找回
- 请勿在公共网络环境中使用，除非配合 IP 白名单 + 强密码

## 贡献

欢迎贡献代码！请提交[Pull Request](https://github.com/hunyanjie/PersonalDAV/compare)。

## 想提意见？

支持[提issue](https://github.com/hunyanjie/PersonalDAV/issues)。

## 许可证

本项目采用MPL-2.0许可证。详见[LICENSE](https://github.com/hunyanjie/PersonalDAV?tab=MPL-2.0-1-ov-file#MPL-2.0-1-ov-file) 文件。

---

通过PersonalDAV，您可以完全掌控自己的联系人信息和日历数据，无需依赖第三方服务。立即开始创建您的私人同步服务吧！
