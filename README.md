# PersonalDAV - 私人CardDAV/CalDAV服务

PersonalDAV是一个带图形界面的私人CardDAV/CalDAV服务，允许您在自己的电脑上轻松管理联系人和日历事件。无需复杂的服务器配置，无需订阅云服务，只需运行此应用程序即可创建您个人的联系人日历同步服务。

## 功能特性

- 🧑 **联系人管理** - 创建、编辑、删除联系人，支持vCard格式
- 📅 **日历事件管理** - 创建、编辑、删除日历事件，支持iCalendar格式
- 🔄 **CardDAV/CalDAV服务** - 通过HTTP提供标准的CardDAV和CalDAV服务
- 📤 **导入/导出功能** -
    - 支持从vCard(.vcf)文件导入联系人
    - 支持从iCalendar(.ics)文件导入事件
    - 支持从URL导入联系人和事件
    - 导出选中的联系人或事件
- 🖥️ **用户友好的GUI** - 使用Tkinter构建的图形界面，支持拖拽导入
- 💾 **本地数据库** - 使用SQLite存储数据，无需额外配置
- 🌐 **跨平台** - 支持Windows、macOS和Linux

> 注意：
> 1：目前只有Windows平台有打包好的程序包，其他平台的请自行打包
> 2：目前DAV功能尚不完善，尽请期待

## 安装与运行

### 前提条件

- Python 3.7+
- 所需的Python库：请参考requirements.txt

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

## 客户端配置

### CardDAV 配置

- 服务器地址: `http://localhost:8000/contacts/`
- 用户名: (任意)
- 密码: (任意)

### CalDAV 配置

- 服务器地址: `http://localhost:8000/events/`
- 用户名: (任意)
- 密码: (任意)

## 技术栈

- **GUI框架**: Tkinter
- **数据格式**: vCard (vcf), iCalendar (ics)
- **数据库**: SQLite
- **HTTP服务器**: Python内置HTTPServer
- **依赖库**:
    - `vobject` - vCard和iCalendar解析
    - `pytz` - 时区处理
    - `python-dateutil` - 日期解析
    - `requests` - HTTP请求
    - `tzlocal` - 本地时区信息
    - `babel` - 日期和时间的国际化
    - `tkcalendar` - 日历选择控件
    - `tkinterdnd2` - 拖拽支持

## 注意事项

- 该服务仅设计用于本地网络或个人使用
- 目前不包含用户认证机制
- 请勿在公共网络环境中使用，除非您添加了适当的认证机制

## 贡献

欢迎贡献代码！请提交[Pull Request](https://github.com/hunyanjie/PersonalDAV/compare)。

## 想提意见？

支持[提issue](https://github.com/hunyanjie/PersonalDAV/issues)。如果是愿望，不一定会实现呦~

## 许可证

本项目采用MPL-2.0许可证。详见[LICENSE](https://github.com/hunyanjie/PersonalDAV?tab=MPL-2.0-1-ov-file#MPL-2.0-1-ov-file)
文件。

---

通过PersonalDAV，您可以完全掌控自己的联系人信息和日历数据，无需依赖第三方服务。立即开始创建您的私人同步服务吧！