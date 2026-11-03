# dsh-privacy-guard

个人智能体（Agent）隐私防护插件，面向 [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness) 运行时。采用「一切皆插件」架构，在 Agent 的输入 / 输出 / 动作三条路径上建立隐私防线。

## 能力总览

| 能力 | 模块 | 说明 |
|---|---|---|
| PII 检测与动态脱敏 | `lib/detectors.js` | 手机号 / 身份证 / 邮箱 / 银行卡 / IPv4 等 PII，以及 OpenAI Key / JWT / AWS Key / GitHub Token / 口令赋值 / Bearer 头等密钥凭据；支持按类别配置掩码策略（保留首尾、全打码、固定占位、邮箱域名保留） |
| 提示词注入检测 | `lib/injection.js` | 中英文双语的「忽略指令 / 角色接管 / 诱导泄露密钥 / 数据外带 / 高危系统动作」检测，输出评分与命中原因 |
| 敏感操作审批拦截 | `lib/approval.js` | 对将要执行的动作（`rm -rf`、批量删除、覆盖源码、数据外发、读凭据、关机格式化等）按风险分输出 `allow / ask / block` 决策 |
| 审计日志 | `lib/audit.js` | 结构化审计事件（脱敏 / 注入 / 审批 / 出境），默认内存队列，可配置 JSONL 落盘并自动轮转 |

## 目录结构

```
dsh-privacy-guard/
├── package.json          # bundle 清单（dsh.bundle 声明）
├── cordis.patch.yml     # DSH 装配声明（--patch 或安装到 plugins 目录）
├── lib/
│   ├── index.js         # 插件入口：apply(ctx)、事件挂钩、注册 guard_* 工具
│   ├── detectors.js     # PII/密钥检测与脱敏引擎
│   ├── injection.js     # 提示词注入检测
│   ├── approval.js      # 敏感操作审批决策
│   └── audit.js         # 审计日志（内存/JSONL）
├── test/                # node:test 单元测试（36 项全通过）
└── references/
    └── THREAT-MODEL.md  # 威胁模型与防护设计说明
```

## 安装（两种方式）

### 方式一：patch 方式（开发调试）

```bash
# 在 DSH 仓库根目录
pnpm dsh web --patch ./dsh-privacy-guard/cordis.patch.yml
```

启动后访问 `http://127.0.0.1:3080`，终端可见 `[privacy-guard] plugin loaded!`。

### 方式二：bundle 安装（正式使用）

把本目录（或其打包产物）放入 DSH 的插件搜索路径：

- Linux: `~/.local/share/deepseek-harness/plugins/`
- macOS: `~/Library/Application Support/DeepSeekHarness/plugins/`
- Windows: `%APPDATA%\DeepSeekHarness\plugins`

也可通过 DSH 插件市场（dsh-market / `dsh plugin add <path>`）安装。

## 配置

在 `cordis.patch.yml` 或 DSH profile 配置中可覆盖：

```yaml
- select:
    - id: privacy-guard
      name: './lib/index.js'
      config:
        privacyGuard:
          logDir: './.dsh-privacy-audit'  # 审计日志落盘目录；不填则仅内存
          silent: false
```

## 暴露的工具

插件向 Agent 注册三个工具，模型可主动调用：

| 工具 | 作用 |
|---|---|
| `guard_redact` | 对文本做 PII 脱敏，返回脱敏后文本与命中数量 |
| `guard_check_injection` | 检测文本是否含注入，返回 `{flagged, reasons, score}` |
| `guard_check_action` | 对动作做风险审批，返回 `{decision, reasons, score}` |

事件挂钩（`agent/request`、`tools/result` 等，防御式监听）：外部输入回灌模型前自动做注入检测与 PII 脱敏，命中注入则写审计告警。

## 开发与测试

```bash
npm test          # 36 项单元测试（无需 DSH 运行时，node >= 20）
```

## 适用范围与边界

- 检测为启发式正则 + 行为评分，会努力降低误报（示例号黑名单过滤、区分 JSON 包裹与真实命令），但不保证 100% 完备；关键场景建议与语义检测（LLM 分类器）叠加。
- 本插件提供**决策与标记**能力；阻断 / 审批 UI 需要 DSH 运行时按 `decision=block` 的结果联动人工确认流程。
- 审计日志中的敏感匹配文本已做脱敏，不记录原始 PII。

## License

MIT
