// test/detectors.test.js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { detectPii, redactText, hasSecrets } from '../lib/detectors.js'

test('检测中国大陆手机号并脱敏（保留 3-3）', () => {
  const text = '联系我 13812345678，或备用 139 9876 5432。'
  const findings = detectPii(text)
  const phones = findings.filter((f) => f.type === 'phone_cn')
  assert.equal(phones.length, 2)
  for (const p of phones) {
    assert.match(p.masked, /^\d{3}\*{5}\d{3}$/)
  }
})

test('示例号（13800000000）不判定为敏感', () => {
  const text = '样例：13800000000'
  const findings = detectPii(text)
  assert.equal(findings.filter((f) => f.type === 'phone_cn').length, 0)
})

test('检测身份证号并脱敏', () => {
  const text = '证件号 11010519491231002X 已登记。'
  const findings = detectPii(text)
  const id = findings.find((f) => f.type === 'id_card')
  assert.ok(id, '应命中身份证规则')
  assert.match(id.masked, /^\d{3}\*{12}\d{2}[0-9Xx]$/)
})

test('检测邮箱并保留域名', () => {
  const text = '发到 zhangsan@example.com 即可。'
  const findings = detectPii(text)
  const email = findings.find((f) => f.type === 'email')
  assert.ok(email)
  assert.equal(email.masked, 'z******n@example.com')
  assert.ok(!email.masked.includes('zhangsan'))
})

test('检测 OpenAI API Key（sk-）并全打码', () => {
  const text = 'sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const findings = detectPii(text)
  const key = findings.find((f) => f.type === 'openai_api_key')
  assert.ok(key)
  assert.equal(key.masked, '*'.repeat(text.length))
})

test('检测 JWT 并全打码', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz12'
  const findings = detectPii(jwt)
  assert.ok(findings.some((f) => f.type === 'jwt'))
})

test('检测口令赋值并只打码值', () => {
  const text = 'password=supersecret123 and api_key=abcdef123456'
  const findings = detectPii(text)
  const kv = findings.filter((f) => f.type === 'generic_password_kv')
  assert.equal(kv.length >= 1, true)
  // 值部分应被替换
  assert.ok(kv.some((f) => f.masked === '[REDACTED]' || f.masked.includes('*')))
})

test('redactText 整段替换', () => {
  const text = '用户 13812345678 的邮箱 a@b.com 和身份证 11010519491231002X。'
  const { text: out, matched } = redactText(text)
  assert.ok(matched >= 3, `matched 应>=3，实际 ${matched}`)
  assert.ok(!out.includes('13812345678'))
  assert.ok(!out.includes('a@b.com'))
  assert.ok(!out.includes('11010519491231002X'))
})

test('hasSecrets 识别密钥类', () => {
  assert.equal(hasSecrets('sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), true)
  assert.equal(hasSecrets('普通文本没有密钥'), false)
})

test('空白输入安全返回', () => {
  assert.deepEqual(detectPii(''), [])
  assert.deepEqual(redactText(''), { text: '', matched: 0 })
})
