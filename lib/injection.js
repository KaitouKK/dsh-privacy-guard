// lib/injection.js
// 提示词注入检测：识别外部数据（网页、文档、消息）中试图劫持智能体行为的指令模式。
// 策略：中英文关键词/短语命中 + 高危行为动作组合评分。关键词可配置增删。

/**
 * 注入检测结果：
 * { flagged: boolean, score: number, reasons: string[], matched: string[] }
 */

/** 直接指令类：让模型忽略/改写自身设定 */
const DIRECTIVE_PATTERNS = [
  { pattern: /ignore (all )?(previous|prior|above|earlier) (instructions?|prompt|context)/i, name: '忽略此前指令' },
  { pattern: /disregard (all )?(previous|prior|above) (instructions?|prompt|context)/i, name: '无视此前指令' },
  { pattern: /forget (all |everything )?(your|the|previous) (instructions?|system prompt|rules)/i, name: '忘记系统设定' },
  { pattern: /you are now /i, name: '角色切换命令' },
  { pattern: /act as (if )?(you are|an? (human|assistant))/i, name: '角色扮演命令' },
  { pattern: /from now on you (are|will|should)/i, name: '改写行为设定' },
  { pattern: /now (you are|you'?re|behave|respond) as/i, name: '指令劫持' },
  // 中文
  { pattern: /忽略(?:所有|以上|之前|一切|\s)*指令/, name: '忽略指令(中文)' },
  { pattern: /无视(?:所有|以上|之前)?(?:指令|规则|要求)/, name: '无视指令(中文)' },
  { pattern: /(忘记|清除)(?:所有|以上)?(?:指令|规则|设定|记忆)/, name: '清除设定(中文)' },
  { pattern: /从现在开始你是?/, name: '改写身份(中文)' },
  { pattern: /你(是|现在是|将扮演|现在扮演)(?:新的)?(?:一个)?(?:角色|身份)/, name: '角色接管(中文)' },
  { pattern: /你(?:现在)?(?:是|已成为)?一个(?:没有限制|不受约束|无限制|自由的)/, name: '无限制模型(中文)' },
  { pattern: /不要(遵守|听从|执行)(你)?(的)?(系统|系统提示)?(指令|规则|限制)/, name: '拒绝系统指令(中文)' },
]

/** 泄密/外带类：诱导模型输出密钥、记忆、私密数据或发往外部 */
const EXFILTRATION_PATTERNS = [
  { pattern: /(print|show|reveal|output|display|leak|extract|send) (your|the|all) (api[ _-]?keys?|secrets?|tokens?|passwords?|credentials?|private keys?)/i, name: '诱导泄露密钥' },
  { pattern: /include (your|the) (api[ _-]?key|secret|token|password|private key) in (the )?(response|answer|output)/i, name: '要求输出凭据' },
  { pattern: /(copy|send|upload|post|forward|exfiltrate|transfer|move) (all |the |every |any )?(data|files?|content|information|conversation|documents?|records?)( |,|\.|$)/i, name: '外带数据' },
  { pattern: /\b(upload|send|post|push) (all|everything|these|those|the (whole|entire) |every)\b.*(to|via|at)\b/i, name: '外带数据(泛指)' },
  { pattern: /(reveal|share|disclose|dump) (your|the|this|my|user'?s) (memory|conversation history|chat logs|previous messages|private data)/i, name: '诱导记忆泄密' },
  // 中文
  { pattern: /(输出|显示|打印|复制|告诉我)(你的一|你的|所有)?(api[_-]?key|密钥|令牌|密码|凭据|私钥)/i, name: '诱导泄露密钥(中文)' },
  { pattern: /把(所有|全部)?(数据|文件|内容|聊天记录|历史消息)发(送)?(给|到)/i, name: '数据外带(中文)' },
  { pattern: /(说出|泄露|透露|回顾)(你的|我的|用户的)?(记忆|隐私|聊天记录|历史对话)/i, name: '记忆诱导(中文)' },
]

/** 高危行为动作：单独出现有风险，组合/含直接指令时升级 */
const HIGH_RISK_ACTIONS = [
  { pattern: /\b(rm|delete|remove|unlink)\s+-rf\b/i, name: '强制递归删除' },
  { pattern: /\b(rm|del|delete|erase)\b.*\b(\/|~|\.\.[\\/]).*/i, name: '删除路径文件' },
  { pattern: /\b(shutdown|reboot|poweroff|halt)\b/i, name: '关机/重启' },
  { pattern: /\b(mkfs|format)\b/i, name: '格式化磁盘' },
  { pattern: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|python)\b/i, name: '下载并执行' },
  { pattern: /\b(chmod\s+777|chown\s+[^ ]+\s+\/)\b/i, name: '高危权限变更' },
  { pattern: /\b(\.git\s+config|~\/\.ssh|id_rsa|id_ed25519)\b/i, name: '触碰密钥文件' },
  { pattern: /\b(env|export)\b.*\b(AWS_|OPENAI|ANTHROPIC|GITHUB_|API_KEY|TOKEN)/, name: '读取环境密钥' },
  { pattern: /\b(open|read|cat|print)\b.*\b(\.env|credentials\.json|config\.ya?ml)\b/i, name: '读取凭据文件' },
  // 中文动作
  { pattern: /(删除|清空|移除|卸载).*(所有|全部|整个|根|磁盘|系统|数据库)/, name: '高风险删除(中文)' },
  { pattern: /(格式化|初始化).*(磁盘|硬盘|系统)/, name: '格式化(中文)' },
  { pattern: /(读取|打开|执行).*(\.env|密钥文件|凭据|credentials)/i, name: '读取凭据(中文)' },
  { pattern: /(发送|上传|同步).*(所有|全部).*(文件|数据)/i, name: '大范围外发(中文)' },
]

/**
 * 检测文本中的注入。
 * @param {string} text
 * @param {number} [threshold=1] 判定阈值：命中条数/权重
 * @returns {{flagged: boolean, score: number, reasons: string[], matched: string[]}}
 */
export function detectInjection(text, threshold = 1) {
  if (typeof text !== 'string' || !text) {
    return { flagged: false, score: 0, reasons: [], matched: [] }
  }
  const reasons = []
  const matched = []

  const check = (list, weight) => {
    for (const rule of list) {
      if (rule.pattern.test(text)) {
        if (!reasons.includes(`${weight}:${rule.name}`)) {
          reasons.push(rule.name)
          matched.push(rule.pattern.source)
        }
      }
    }
  }

  check(DIRECTIVE_PATTERNS, 3)
  check(EXFILTRATION_PATTERNS, 3)
  check(HIGH_RISK_ACTIONS, 1)

  // 打分：全局禁用 g 标志，直接用 test 结果计数
  const score = reasons.length
  return {
    flagged: score >= threshold,
    score,
    reasons,
    matched,
  }
}
