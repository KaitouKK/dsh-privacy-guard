// test/audit.test.js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAuditor, readAuditLog, SEVERITY_CRITICAL } from '../lib/audit.js'

test('内存模式记录与查询', () => {
  const a = createAuditor({})
  a.record({ kind: 'injection', severity: SEVERITY_CRITICAL, detail: '注入告警' })
  const recent = a.getRecent()
  assert.equal(recent.length, 1)
  assert.equal(recent[0].detail, '注入告警')
  assert.ok(recent[0].ts)
  a.close()
})

test('落盘模式写入 JSONL 并可回读', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pg-audit-'))
  const a = createAuditor({ logDir: dir })
  a.record({ kind: 'approval', severity: 2, detail: '审批拦截', action: 'bash' })
  a.close()

  const files = ['privacy-guard-audit.jsonl']
  assert.ok(existsSync(join(dir, files[0])))

  const records = readAuditLog(join(dir, files[0]))
  assert.equal(records.length, 1)
  assert.equal(records[0].action, 'bash')
})

test('不可写目录退化为内存模式', () => {
  // /proc 下不可写
  const a = createAuditor({ logDir: '/proc/definitely-not-writable' })
  a.record({ kind: 'info', detail: 'x' })
  assert.equal(a.getRecent().length, 1)
  a.close()
})
