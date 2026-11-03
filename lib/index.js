// lib/index.js
// dsh-privacy-guard —— DSH 个人智能体隐私防护插件。
//
// 能力：
//   1. PII 检测与动态脱敏（手机号/身份证/邮箱/银行卡/密钥/Token…）
//   2. 提示词注入检测（中英文，忽略指令/泄密外带/高危动作）
//   3. 敏感操作审批拦截（删除/外发/凭据/关机等按风险分决策）
//   4. 审计日志（默认内存，可配置落盘 JSONL）
//
// 插件形态遵循 Cordis/DSH 规范：导出 { name, inject, apply }。
// 事件挂钩采用防御式设计：列出可能的事件名（agent/request、tools/result 等），
// 实际可用性以运行时为准；即使某个事件不存在，插件也能正常加载。
// 同时导出独立函数便于单元测试与其它插件复用。

import { detectPii, redactText } from './detectors.js'
import { detectInjection } from './injection.js'
import { evaluateApproval, describeRisk } from './approval.js'
import { createAuditor, SEVERITY_INFO, SEVERITY_WARN, SEVERITY_CRITICAL } from './audit.js'

export const name = 'privacy-guard'
export const inject = ['tools'] // 依赖工具注册表（若运行时不提供则降级）

/**
 * 对一段文本执行全部隐私防线，返回处理结果。
 * 供测试与其它插件直接调用；DSH 事件挂钩也会调用它。
 * @param {string} text
 * @param {object} [options] { redactPii=true, detectInjection=true }
 */
export function guardText(text, options = {}) {
  const { redactPii: doRedact = true, detectInjection: doInjection = true } = options
  const findings = {
    pii: [],
    injection: null,
    redacted: '',
  }

  if (doInjection) {
    findings.injection = detectInjection(text)
  }

  if (doRedact) {
    const { text: redacted, matched } = redactText(text)
    if (matched > 0) {
      findings.pii = detectPii(text)
    }
    findings.redacted = redacted
  } else {
    findings.redacted = text
  }

  return findings
}

/**
 * 对一次工具调用做审批评估。
 * @param {string} action 动作名
 * @param {object|string} args
 */
export function checkAction(action, args) {
  return evaluateApproval(action, args)
}

/**
 * Cordis 插件入口。
 * @param {object} ctx DSH/Cordis 上下文
 */
export function apply(ctx) {
  const runtimeConfig = ctx?.config?.privacyGuard ?? {}
  const auditor = createAuditor({
    logDir: runtimeConfig.logDir || '',
    silent: runtimeConfig.silent !== false,
  })

  const log = (entry) => {
    try {
      auditor.record(entry)
    } catch (err) {
      /* 审计失败不应影响主流程 */
    }
  }

  // ---- 1. 拦截/清洗外部输入（工具结果、用户消息） ----
  // 事件名参考 DSH 事件系统：agent/request（模型请求前）、tools/result（工具返回后）。
  // 用防御式三元监听：能监听则监听，事件不存在也仅静默失败。
  const hookInjection = (payload) => {
    try {
      if (!payload || typeof payload !== 'object') return payload
      const textish =
        payload.content ??
        payload.text ??
        payload.message ??
        (typeof payload === 'string' ? payload : JSON.stringify(payload))

      if (typeof textish !== 'string') return payload
      const result = guardText(textish, { redactPii: true, detectInjection: true })

      // 注入告警：记录并标记（由上层策略决定是否阻断）
      if (result.injection?.flagged) {
        log({
          kind: 'injection',
          severity: SEVERITY_CRITICAL,
          detail: `检测到提示词注入（${result.injection.reasons.join('、')}）`,
          source: 'inbound',
        })
        if (payload?.danger && typeof payload.danger === 'object') {
          payload.danger.injectionFlagged = true
        }
      }

      // 脱敏：若输出字段存在则替换
      if (payload?.content && typeof payload.content === 'string') {
        payload.content = result.redacted
      }
      return payload
    } catch (err) {
      return payload // 任何异常都放行，避免防护自身成为故障点
    }
  }

  const eventNames = ['agent/request', 'tools/result', 'tool/result', 'session/message']
  for (const evt of eventNames) {
    try {
      if (typeof ctx?.on === 'function') {
        ctx.on(evt, hookInjection)
      }
    } catch (err) {
      /* 事件不存在/类型不匹配 → 静默跳过 */
    }
  }

  // ---- 2. 注册防护工具：让模型可主动调用脱敏/评估 ----
  const toolsService = ctx?.tools
  const makeToolName = (n) => `guard_${n}`

  const toolObjects = [
    {
      name: makeToolName('redact'),
      description: '对文本做 PII 脱敏：识别手机号/身份证/邮箱/银行卡/API 密钥/Token 等并打码，返回原结果与命中数量。',
      version: '0.1.0',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: '待脱敏文本' },
        },
        required: ['text'],
      },
      async execute(args) {
        if (!args.text) return { error: '缺少 text 参数' }
        const { text, matched } = redactText(args.text)
        return { text, matched }
      },
    },
    {
      name: makeToolName('check_injection'),
      description: '检测文本是否包含提示词注入（忽略指令/诱导泄露/高危动作），返回是否标记与原因。',
      version: '0.1.0',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: '待检测文本' },
        },
        required: ['text'],
      },
      async execute(args) {
        if (!args.text) return { error: '缺少 text 参数' }
        const r = detectInjection(args.text)
        return { flagged: r.flagged, reasons: r.reasons, score: r.score }
      },
    },
    {
      name: makeToolName('check_action'),
      description: '对将要执行的动作（工具名+参数）做风险审批评估，返回 allow/ask/block 决策与原因。',
      version: '0.1.0',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', description: '动作名，如 bash、write_file' },
          args: { type: 'object', description: '参数对象或文本' },
        },
        required: ['action'],
      },
      async execute(args) {
        const r = evaluateApproval(args.action || '', args.args || {})
        return { decision: r.decision, reasons: r.blockReasons, score: r.score, hint: describeRisk(r.decision) }
      },
    },
  ]

  try {
    if (toolsService && typeof toolsService.register === 'function') {
      for (const t of toolObjects) {
        try {
          toolsService.register(t)
        } catch (err) {
          /* 单个工具注册失败不影响其它 */
        }
      }
    }
  } catch (err) {
    /* tools 服务不可用 → 跳过注册（事件防护仍生效） */
  }

  // ---- 3. 暴露审计记录查询 ----
  ctx.getRecentAudit = () => auditor.getRecent()

  // 卸载清理（Cordis 自动清理事件监听；这里提供显式接口）
  return {
    dispose() {
      try {
        auditor.close()
      } catch (err) {
        /* noop */
      }
    },
  }
}
