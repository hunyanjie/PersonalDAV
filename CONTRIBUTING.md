# 贡献指南

感谢您对 PersonalDAV 感兴趣！以下是一些贡献指南。

## 报告问题

- 搜索 [Issues](https://github.com/hunyanjie/PersonalDAV/issues) 确认是否已有相同报告
- 提供复现步骤、操作系统、Python 版本等信息
- 如有相关日志，一并附上

## 提交 Pull Request

1. Fork 仓库并创建特性分支
2. 确保代码风格一致（参考现有代码）
3. 运行测试确保不破坏现有功能：
   ```bash
   python tests/run_all.py
   ```
4. 提交 PR 时说明改动目的和实现方式

## 开发环境

### 安装依赖

```bash
pip install -e ".[dev]"
```

### 代码规范

- Python 3.10+，使用类型注解
- 新代码须通过 `mypy --strict` 检查
- 导入顺序：标准库 → 第三方 → 本地模块
- 类名 `PascalCase`，函数/变量 `snake_case`

### 运行测试

```bash
python tests/run_all.py
```

测试涵盖：pytest 单元测试（23 项）、MCP 工具测试（33 个工具）、HTTP 端到端测试、鉴权测试。

### 提交信息

- 使用中文描述改动
- 格式：`类型(模块): 描述`
- 类型：`feat` `fix` `refactor` `perf` `docs` `test` `chore`
- 示例：`feat(db): SQLite WAL 定期 checkpoint`

## 项目结构

参考 [README 中的架构图](README.md#项目架构)。
