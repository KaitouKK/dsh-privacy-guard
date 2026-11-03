// lib/approval.js
// 敏感操作审批拦截：识别智能体即将执行的高风险动作，决定是否需要人工确认。
// 规则按「动作类型」+「对象路径/关键词」评分；可在配置中调整阈值与规则启停。

/**
 * 审批决策结果：
 * {
 *   decision: 'allow' | 'ask' | 'block',
 *   blockReasons: string[],   // 必须人工确认的原因
 *   score: number,            // 累计风险分
 * }
 */

/** 单条规则：{ id, weight, name, matcher(action, args) } */
export const APPROVAL_RULES = [
  {
    id: 'delete_force',
    weight: 90,
    name: '强制删除（rm -rf）',
    matcher: (action, argsText) => /rm\s+-rf\b|del\s*\/[fsq]|Remove-Item\s+-Recurse/.test(action + ' ' + argsText),
  },
  {
    id: 'delete_bulk',
    weight: 60,
    name: '批量删除',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(rm|del|delete|rmdir|Remove-Item|unlink)\b/.test(t) &&
             (/[*?{}]|\d{2,}\s*(files?|items?|rows?|records?)|(^|[^a-z])(all|many|every|全部|所有|批量|多)/i.test(t))
    },
  },
  {
    id: 'file_overwrite_code',
    weight: 55,
    name: '覆盖源码/配置',
    matcher: (action, argsText) => {
      const t = `${action} ${argsText}`
      const actionWord = (action || '').replace(/[^a-z]+/gi, ' ').trim()
      return /(^|\s)(write|echo|cat|set-content|cp|mv|scp|edit|create|update|overwrite)(\s|$)/i.test(actionWord + ' ' + argsText) &&
             /\.(js|ts|py|go|rs|java|json|ya?ml|toml|config|env|sh|conf)(\s|$|['"])/i.test(t)
    },
  },
  {
    id: 'network_exfil',
    weight: 80,
    name: '数据外发/上传',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(curl|wget|scp|rsync|git\s+push|nc|ncat|smtp|mail|telegram|webhook|http|https)\b/i.test(t) &&
             /\b(upload|send|post|push|put|transfer|外发|上传|发送)\b/i.test(t)
    },
  },
  {
    id: 'credential_access',
    weight: 85,
    name: '读取凭据/环境密钥',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(env|printenv|export|cat|open|read)\b/i.test(t) &&
             /(\.env|credentials|secret|password|api[_-]?key|token|id_rsa|id_ed25519|\.npmrc|\.ssh)/i.test(t)
    },
  },
  {
    id: 'system_shutdown',
    weight: 95,
    name: '关机/重启/格式化',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(shutdown|reboot|poweroff|halt|mkfs|format|crontab\s+-[er])\b/i.test(t)
    },
  },
  {
    id: 'package_untrusted',
    weight: 50,
    name: '安装来源不明的软件包',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(npm|pnpm|yarn|pip|pip3|go\s+install|curl|wget)\b/i.test(t) &&
             /(\|\s*(sh|bash)|--unsafe-perm|-U\b|--upgrade|--force|-f\b)/i.test(t)
    },
  },
  {
    id: 'user_dir_wide',
    weight: 45,
    name: '整目录遍历/删除',
    matcher: (action, argsText) => {
      const t = action + ' ' + argsText
      return /\b(find|rg|grep|ls|du|tree|rm)\b/.test(t) &&
             /[\w\d./-]*(\*|\?)|\/(home|Users|Documents|Desktop|下载|文档)\b/i.test(t)
    },
  },
]

/**
 * 评估一次工具调用是否需要审批。
 * @param {string} action 动作名（工具名/命令）
 * @param {object|string} args 参数对象或参数字符串
 * @param {object} [opts] { askThreshold=50, blockThreshold=80 }
 * @returns {{decision:'allow'|'ask'|'block', blockReasons:string[], score:number}}
 */
export function evaluateApproval(action, args, opts = {}) {
  const { askThreshold = 50, blockThreshold = 80 } = opts
  let argsText = ''
  if (typeof args === 'string') argsText = args
  else if (args && typeof args === 'object') {
    // 优先提取命令类参数（bash/execute 的 command、shell、cmd 等），
    // 避免 JSON 包裹的 { } 被误判为通配符；其余对象再 stringify。
    const cmdKey = ['command', 'cmd', 'shell', 'exec', 'program', 'source']
      .map((k) => args[k])
      .find((v) => typeof v === 'string')
    if (cmdKey) {
      argsText = cmdKey
      // 路径类参数也纳入评估（如 write_file 的 path、工具名 file 等）
      const extra = ['path', 'file', 'dest', 'target', 'dir', 'url']
        .map((k) => args[k])
        .filter((v) => typeof v === 'string')
      if (extra.length) argsText += ' ' + extra.join(' ')
    } else {
      try {
        argsText = JSON.stringify(args)
      } catch {
        argsText = String(args)
      }
    }
  }

  const blockReasons = []
  let score = 0
  for (const rule of APPROVAL_RULES) {
    let hit = false
    try {
      hit = rule.matcher(action, argsText)
    } catch {
      hit = false
    }
    if (hit) {
      score += rule.weight
      blockReasons.push(rule.name)
    }
  }

  let decision = 'allow'
  if (blockReasons.length > 0 && score >= blockThreshold) decision = 'block'
  else if (blockReasons.length > 0 && score >= askThreshold) decision = 'ask'

  return { decision, blockReasons, score }
}

/** 判断一段文本是否为高风险操作（供注入检测与审批共用语义） */
export function describeRisk(decision) {
  switch (decision) {
    case 'block': return '高风险：需要人工确认才能执行'
    case 'ask': return '中风险：建议人工确认'
    default: return '低风险：可自动执行'
  }
}
