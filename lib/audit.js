// lib/audit.js
// 审计日志：把脱敏、注入告警、审批决策、出境事件写为本地结构化记录。
// 日志存储：用户可配置目录，默认不落盘（audio 环境可用内存队列）。
// 使用零依赖实现，便于 DSH/Node 直接加载与测试。

import { appendFileSync, mkdirSync, writeFileSync, existsSync, readFileSync, statSync } from 'node:fs'

/**
 * 审计事件：
 * {
 *   ts, kind: 'redact'|'injection'|'approval'|'export',
 *   action?, type?/rule?, detail, severity: 1|2|3, source?
 * }
 */

export const SEVERITY_INFO = 1
export const SEVERITY_WARN = 2
export const SEVERITY_CRITICAL = 3

function pad2(n) {
  return String(n).padStart(2, '0')
}

export function nowIso() {
  const d = new Date()
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}Z`
}

/**
 * 创建审计器。
 * @param {object} [opts] { logDir?: string, maxBytes?: number, silent?: boolean }
 *  - logDir 为空 => 仅内存队列（默认）；提供目录 => JSON Lines 落盘。
 * @returns {object} { record(entry), flush(), getRecent(), close() }
 */
export function createAuditor(opts = {}) {
  const { logDir = '', maxBytes = 5 * 1024 * 1024, silent = false } = opts
  const memory = []

  let logStream = null
  if (logDir) {
    // 伪文件系统（/proc /sys 等）禁止 mkdir，直接降级内存，避免挂起
    const pseudoFS = /^\/(proc|sys|dev|run|tmpfs)(\/|$)/.test(logDir)
    try {
      if (!pseudoFS && !existsSync(logDir)) {
        mkdirSync(logDir) // 非递归，仅当父目录存在且可写时成功，避免在伪文件系统上递归
      }
      const file = `${logDir}/privacy-guard-audit.jsonl`
      writeFileSync(file, '', { flag: 'a' })
      logStream = { file }
    } catch (err) {
      if (!silent) console.warn(`[privacy-guard] 审计目录不可用，改内存模式: ${err.message}`)
      logStream = null
    }
  }

  const record = (entry) => {
    const evt = {
      ts: nowIso(),
      ...entry,
    }
    memory.push(evt)
    if (memory.length > 1000) memory.shift()

    if (logStream) {
      try {
        const line = JSON.stringify(evt) + '\n'
        // 简单轮转：超过 maxBytes 则归档
        let size = 0
        try {
          size = statSync(logStream.file).size
        } catch {
          size = 0
        }
        if (size + line.length > maxBytes) {
          const old = `${logStream.file}.${Date.now()}`
          try {
            const data = readFileSync(logStream.file)
            writeFileSync(old, data)
            writeFileSync(logStream.file, '')
          } catch (err) {
            if (!silent) console.warn(`[privacy-guard] 日志轮转失败: ${err.message}`)
          }
        }
        appendFileSync(logStream.file, line)
      } catch (err) {
        if (!silent) console.warn(`[privacy-guard] 审计写入失败: ${err.message}`)
      }
    }
    return evt
  }

  const getRecent = (limit = 200) => memory.slice(-limit)

  const flush = () => {} // append 即时落盘，无缓存

  const close = () => {
    logStream = null
  }

  return { record, flush, getRecent, close }
}

/** 从 JSONL 审计文件读取解析（供展示/报告） */
export function readAuditLog(filePath) {
  if (!filePath || !existsSync(filePath)) return []
  const raw = readFileSync(filePath, 'utf8')
  return raw.split('\n').filter(Boolean).map((line) => {
    try {
      return JSON.parse(line)
    } catch {
      return null
    }
  }).filter(Boolean)
}
