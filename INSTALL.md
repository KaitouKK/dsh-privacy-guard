# dsh-privacy-guard 安装指引

> 个人智能体隐私防护插件：PII 检测与动态脱敏、提示词注入检测、敏感操作审批拦截、审计日志。
> 面向 DeepSeek Harness (DSH) 运行时。

---

## 方式一：从 GitHub 克隆（推荐，无需 npm）

```bash
# 1. 克隆到本地（仓库为公开仓库，无需任何凭据）
git clone https://github.com/KaitouKK/dsh-privacy-guard.git

# 2. 把插件目录放进 DSH 的插件目录（~/.dsh/plugins 需自行创建）
mkdir -p ~/.dsh/plugins
cp -r dsh-privacy-guard ~/.dsh/plugins/

# 3. 注册到 web profile（编辑 ~/.dsh/profiles/web/cordis.patch.yml，顶部加入：）
```

编辑 `~/.dsh/profiles/web/cordis.patch.yml`：

```yaml
- insert:
    - id: privacy-guard
      name: '/home/<你的用户名>/.dsh/plugins/dsh-privacy-guard/lib/index.js'
      # 可选配置：
      # config:
      #   privacyGuard:
      #     logDir: '/home/<你的用户名>/.dsh/privacy-audit'   # 审计日志落盘目录，默认内存
      #     silent: false
```

> 注意：`name` 必须填**绝对路径**，替换 `<你的用户名>`。

# 4. 启动验证
dsh web --no-open
# 启动日志无 "did not activate" 警告即加载成功
```

## 方式二：patch 方式（开发调试）

```bash
dsh web --patch ./dsh-privacy-guard/cordis.patch.yml
```

## 方式三：直接分发目录

把整个 `dsh-privacy-guard/` 目录（或打包 zip）发给使用者，解压放到 `~/.dsh/plugins/dsh-privacy-guard/`，再按方式一的第 3 步注册即可。

---

## 验证插件是否生效

1. **看启动日志**：无 `warning` / `did not activate` 即激活成功。
2. **查工具集**：插件注册 3 个工具供 Agent 调用：
   - `guard_redact` —— PII 脱敏
   - `guard_check_injection` —— 注入检测
   - `guard_check_action` —— 审批评估
3. **跑单元测试**（需要源码目录）：
   ```bash
   cd dsh-privacy-guard && npm test   # 36 项全通过
   ```

## 配置模型 Key（可选）

完整 Agent 对话需要模型凭据，否则任务会报 `MISSING_CREDENTIAL`：

```bash
export DEEPSEEK_API_KEY=你的Key   # 或启动前写入环境
```

也可以在 `dsh web` 的「设置 → 模型」页面填写。

---

## 能力清单

| 能力 | 说明 |
|---|---|
| PII 检测与脱敏 | 手机号 / 身份证 / 邮箱 / 银行卡 / IPv4 / API Key / JWT / 口令赋值 / Bearer 头 |
| 提示词注入检测 | 中英文：忽略指令 / 角色接管 / 诱导泄密 / 数据外带 / 高危动作 |
| 敏感操作审批 | rm -rf / 批量删除 / 覆盖源码 / 数据外发 / 读凭据 / 关机格式化 → allow/ask/block |
| 审计日志 | 内存或 JSONL 落盘，事件即脱敏，不记录原始 PII |

## 更多信息

- 源码与文档：https://github.com/KaitouKK/dsh-privacy-guard
- 威胁模型与设计取舍：仓库 `references/THREAT-MODEL.md`
