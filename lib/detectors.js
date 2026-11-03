// lib/detectors.js
// PII 检测与脱敏引擎：识别常见个人信息与密钥类型，支持按类别配置掩码策略。
// 纯函数、零依赖，可在 Node 与浏览器环境直接使用，便于单元测试与嵌入。

/**
 * 常用掩码策略：
 * - keepHeadTail: 保留首尾若干位，中间打 *（适合手机号、身份证等）
 * - all: 全部替换为 *
 * - fixed: 替换为固定占位符（如 [REDACTED]）
 * - email: 保留域名与首字符
 */
const MASK_KEEP_HEAD_TAIL = 'keepHeadTail'
const MASK_ALL = 'all'
const MASK_FIXED = 'fixed'
const MASK_EMAIL = 'email'

/**
 * 各类 PII 检测规则。
 * id: 类型标识；name: 展示名；regex: 检测正则（须带 g 或由循环处理）；mask: 脱敏策略；
 * sensitiveLevel: 敏感度（1 低 / 2 中 / 3 高，高敏感在审计中强制记录）。
 * 说明：规则是启发式的，用于降低误判，不追求绝对完备；生产可扩展正则库。
 */
export const PII_RULES = [
  {
    id: 'phone_cn',
    name: '手机号（中国大陆）',
    regex: /(?:^|[^\d])(1[3-9]\d)\s?-?\s?(\d{4})\s?-?\s?(\d{4})(?!\d)/g,
    mask: MASK_KEEP_HEAD_TAIL,
    sensitiveLevel: 3,
  },
  {
    id: 'id_card',
    name: '身份证号（中国大陆）',
    regex: /(?<!\d)(\d{6})(\d{8})(\d{3}[0-9Xx])(?!\d)/g,
    mask: MASK_KEEP_HEAD_TAIL,
    sensitiveLevel: 3,
  },
  {
    id: 'email',
    name: '电子邮箱',
    regex: /\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g,
    mask: MASK_EMAIL,
    sensitiveLevel: 2,
  },
  {
    id: 'bank_card',
    name: '银行卡号',
    regex: /\b(\d{4})(\d{4})(\d{4})(\d{4,})\b/g,
    mask: MASK_KEEP_HEAD_TAIL,
    sensitiveLevel: 3,
  },
  {
    id: 'ipv4',
    name: 'IPv4 地址',
    regex: /\b((?:\d{1,3}\.){3}\d{1,3})\b/g,
    mask: MASK_FIXED,
    sensitiveLevel: 1,
  },
]

/**
 * 密钥/凭据类检测规则（高敏感，检测到即告警）。
 * 词根触发 + 上下文找值：sk-xxx、api_key=xxx、Authorization: Bearer xxx、password=xxx 等。
 */
const SECRET_BASE_PATTERNS = [
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    regex: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
    mask: MASK_ALL,
  },
  {
    id: 'aws_access_key',
    name: 'AWS Access Key',
    regex: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
    mask: MASK_ALL,
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    mask: MASK_ALL,
  },
  {
    id: 'jwt',
    name: 'JWT Token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    mask: MASK_ALL,
  },
  {
    id: 'generic_password_kv',
    name: '口令/密钥赋值',
    regex: /\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*["']?([^"'\s,;]{6,})/gi,
    mask: MASK_FIXED,
  },
  {
    id: 'bearer_auth',
    name: 'Bearer 认证头',
    regex: /\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{12,})/gi,
    mask: MASK_ALL,
  },
]

export const SECRET_RULES = SECRET_BASE_PATTERNS

/** 忽略检测的首页/占位文本，降低误报 */
const PHONE_BLACKLIST = new Set([
  '13800000000', '13900000000', '18800000000', '10000000000',
  '12345678901', '1234567890', '00000000000',
])

/**
 * 检测文本中的 PII。
 * @param {string} text 输入文本
 * @param {object} [options] { categories?: Array<string>, includeSecrets?: boolean }
 * @returns {{type: string, name: string, match: string, masked: string, sensitiveLevel: number}[]}
 */
export function detectPii(text, options = {}) {
  if (typeof text !== 'string' || !text) return []
  const { categories = null, includeSecrets = true } = options
  const results = []

  const rules = [...PII_RULES, ...(includeSecrets ? SECRET_RULES : [])]
  for (const rule of rules) {
    if (categories && !categories.includes(rule.id)) continue
    // 重置全局正则 lastIndex，避免状态残留
    rule.regex.lastIndex = 0
    let m
    while ((m = rule.regex.exec(text)) !== null) {
      // 手机号：捕获组拼接纯号码再脱敏
      let matchText = m[0]
      if (rule.id === 'phone_cn') {
        matchText = `${m[1]}${m[2]}${m[3]}`
        if (PHONE_BLACKLIST.has(matchText)) continue
      }
      // 赋值类口令规则：只脱敏值部分，键名保留
      if (rule.id === 'generic_password_kv' && m[2]) {
        matchText = m[2]
      }
      const masked = maskMatch(rule, matchText)
      results.push({
        type: rule.id,
        name: rule.name,
        match: matchText,
        masked,
        sensitiveLevel: rule.sensitiveLevel ?? 3,
      })
      if (m[0].length === 0) rule.regex.lastIndex++ // 防死循环
    }
  }
  return results
}

/** 对单个匹配结果按策略脱敏 */
export function maskMatch(rule, matchText) {
  switch (rule.mask) {
    case MASK_KEEP_HEAD_TAIL:
      return keepHeadTail(matchText)
    case MASK_ALL:
      return '*'.repeat(matchText.length)
    case MASK_EMAIL:
      return maskEmail(matchText)
    case MASK_FIXED:
      return '[REDACTED]'
    default:
      return keepHeadTail(matchText)
  }
}

/** 保留首尾若干位 */
function keepHeadTail(value) {
  if (value.length <= 4) return '*'.repeat(value.length)
  const head = value.slice(0, 3)
  const tail = value.slice(-3)
  const stars = '*'.repeat(Math.max(value.length - 6, 3))
  return `${head}${stars}${tail}`
}

/** 邮箱脱敏：保留首字符与域名 */
function maskEmail(value) {
  const at = value.indexOf('@')
  if (at <= 0) return '*@*'
  const local = value.slice(0, at)
  const domain = value.slice(at + 1)
  let visibleLocal
  if (local.length <= 2) {
    visibleLocal = local[0] + '*'.repeat(Math.max(local.length - 1, 1))
  } else {
    visibleLocal = `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`
  }
  return `${visibleLocal}@${domain}`
}

/**
 * 对整段文本做脱敏替换，返回 { text, matched }。
 * @param {string} text
 * @param {object} [options]
 * @returns {{text: string, matched: number}}
 */
export function redactText(text, options = {}) {
  if (typeof text !== 'string' || !text) return { text, matched: 0 }
  let result = text
  let matched = 0
  const rules = [...PII_RULES, ...(SECRET_RULES)]
  for (const rule of rules) {
    rule.regex.lastIndex = 0
    result = result.replace(rule.regex, (...args) => {
      const full = args[0]
      if (rule.id === 'generic_password_kv') {
        // 只替换值部分：保持键前缀
        const prefix = full.match(/^[^:=]*[:=]\s*["']?/)[0] ?? ''
        const value = full.slice(prefix.length)
        matched++
        return `${prefix}${maskMatch(rule, value)}`
      }
      if (rule.id === 'phone_cn') {
        const digits = args[1] + args[2] + args[3]
        if (PHONE_BLACKLIST.has(digits)) return full
        matched++
        return args[0].replace(digits, maskMatch(rule, digits))
      }
      matched++
      return maskMatch(rule, full)
    })
  }
  return { text: result, matched }
}

/** 判断是否包含密钥类敏感信息 */
export function hasSecrets(text) {
  return detectPii(text, { categories: SECRET_RULES.map((r) => r.id) }).length > 0
}

export const PII_MASKS = { MASK_KEEP_HEAD_TAIL, MASK_ALL, MASK_FIXED, MASK_EMAIL }
