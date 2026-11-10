// Executed with the generated SDK config on stdin by SDKCompatibilityTests.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')

const config = JSON.parse(fs.readFileSync(0, 'utf8'))
const template = fs.readFileSync(path.join(__dirname, '../templates/authentication/login_ukey.html'), 'utf8')
const script = template.slice(template.indexOf('(function () {'), template.lastIndexOf('</script>'))
  .replace(/{% trans "([^"]*)" %}/g, '$1')
  .replace(/{{ challenge\|[^}]+}}/g, 'server-challenge')
  .replace(/{{ challenge_id\|[^}]+}}/g, 'challenge-id')
  .replace(/{{ ukey_revision\|[^}]+}}/g, config.config.revision)
  .replace(/{{ ukey_provider\|[^}]+}}/g, config.config.provider)
  .replace(/{{ ukey_settings_changed\|[^}]+}}/g, 'Settings changed')
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve)) }

async function page() {
  const calls = []
  const submissions = []
  const timers = new Map()
  const state = { serial: 'device-serial', pin: 0, cert: 'fresh-cert', signature: 'attached-signature' }
  const element = () => ({
    style: {}, parentElement: { style: {} }, value: '', children: [], listeners: {},
    appendChild(child) { this.children.push(child) },
    addEventListener(event, callback) { this.listeners[event] = callback },
    querySelector() { return null }, focus() {},
    submit() { submissions.push(Object.fromEntries(this.children.map(child => [child.name, child.value]))) }
  })
  const elements = new Map()
  let ready
  const document = {
    cookie: '', head: element(), body: element(), createElement: element,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element())
      return elements.get(id)
    },
    addEventListener(event, callback) {
      assert.equal(event, 'DOMContentLoaded')
      ready = callback
    }
  }
  function UKeyAPI() {
    for (const [name, result] of Object.entries({
      UKey_CheckInstall: () => 0, UKey_GetDevSN: () => state.serial,
      UKey_GetVersion: () => '1.0', UKey_VerifyPIN: () => state.pin,
      UKey_GetCert: () => state.cert, UKey_P7SignAttach: () => state.signature
    })) {
      this[name] = (...args) => { calls.push([name, ...args]); return result() }
    }
  }
  const browser = {
    UKeyAPI, location: { href: '/core/auth/ukey/login/' },
    VCTKSCertificateDigest(cert) { assert.equal(cert, state.cert); return 4 }
  }
  const sandbox = {
    window: browser, document, btoa: value => Buffer.from(value).toString('base64'),
    fetch: async url => ({
      ok: true, json: async () => JSON.parse(JSON.stringify(
        url.includes('/settings/public/') ? {} : url.includes('revision_only=1') ? config.config : config
      )),
      text: async () => ''
    }),
    setInterval(callback, interval) {
      assert.equal(interval, 5000)
      timers.set(1, callback)
      return 1
    },
    clearInterval(id) { timers.delete(id) }
  }
  vm.runInNewContext(script, sandbox)
  ready()
  await settle()
  return {
    calls, submissions, state, timers,
    button: document.getElementById('ukey-login-btn'),
    status: document.getElementById('ukey-status-text'),
    async tick() { for (const callback of timers.values()) callback(); await settle() },
    async login() {
      document.getElementById('id_pin').value = '123456'
      document.getElementById('ukey-login-form').listeners.submit({ preventDefault() {} })
      await settle()
    }
  }
}

test('idle login detection keeps polling the device without reading or selecting a certificate', async () => {
  const app = await page()
  for (let i = 0; i < 3; i++) await app.tick()
  assert.deepEqual(app.calls.map(call => call[0]), Array(4).fill([
    'UKey_CheckInstall', 'UKey_GetDevSN', 'UKey_GetVersion'
  ]).flat())
  assert.equal(app.button.disabled, false)
  assert.equal(app.submissions.length, 0)
})

test('unplugging and reconnecting update device status without opening a certificate chooser', async () => {
  const app = await page()
  app.state.serial = ''
  await app.tick()
  assert.equal(app.button.disabled, true)
  app.state.serial = 'another-device'
  await app.tick()
  assert.equal(app.button.disabled, false)
  assert.equal(app.calls.filter(call => call[0] === 'UKey_GetCert').length, 0)
})

test('login refreshes the device, verifies PIN, reads one certificate and signs before submitting', async () => {
  const app = await page()
  app.calls.length = 0
  await app.login()
  assert.deepEqual(app.calls.map(call => call[0]), [
    'UKey_CheckInstall', 'UKey_GetDevSN', 'UKey_GetVersion',
    'UKey_VerifyPIN', 'UKey_GetCert', 'UKey_P7SignAttach'
  ])
  assert.deepEqual(app.calls[3], ['UKey_VerifyPIN', '123456'])
  assert.deepEqual(app.calls[4], ['UKey_GetCert', 1])
  assert.deepEqual(app.calls[5], ['UKey_P7SignAttach', 4, Buffer.from('server-challenge').toString('base64')])
  assert.deepEqual(app.submissions, [{
    signature: 'attached-signature', cert: 'fresh-cert', username: '',
    ukey_sn: 'device-serial', challenge_id: 'challenge-id'
  }])
  const count = app.calls.length
  await app.tick()
  assert.equal(app.calls.length, count)
})

test('wrong PIN does not read certificates, sign or submit; idle polling never retries selection', async () => {
  const app = await page()
  app.state.pin = 1
  await app.login()
  await app.tick()
  assert.equal(app.calls.filter(call => call[0] === 'UKey_GetCert').length, 0)
  assert.equal(app.calls.filter(call => call[0] === 'UKey_P7SignAttach').length, 0)
  assert.equal(app.submissions.length, 0)
  app.state.pin = 0
  await app.login()
  assert.equal(app.submissions.length, 1)
})

test('cancelled or failed certificate reads never sign stale data and only retry on another login click', async () => {
  const app = await page()
  app.state.signature = ''
  await app.login()
  assert.equal(app.submissions.length, 0)
  app.state.cert = ''
  app.state.signature = 'new-signature'
  await app.login()
  for (let i = 0; i < 3; i++) await app.tick()
  assert.equal(app.calls.filter(call => call[0] === 'UKey_GetCert').length, 2)
  assert.equal(app.calls.filter(call => call[0] === 'UKey_P7SignAttach').length, 1)
  assert.equal(app.submissions.length, 0)
  app.state.cert = 'another-cert'
  await app.login()
  assert.equal(app.submissions[0].cert, 'another-cert')
})

test('a device removed just before login stops before PIN, certificate export and signing', async () => {
  const app = await page()
  app.calls.length = 0
  app.state.serial = ''
  await app.login()
  assert.deepEqual(app.calls.map(call => call[0]), ['UKey_CheckInstall', 'UKey_GetDevSN'])
  assert.equal(app.submissions.length, 0)
})

test('configuration changes stop detection and prevent login with the obsolete profile', async () => {
  const app = await page()
  const revision = config.config.revision
  try {
    config.config.revision = 'changed-revision'
    const count = app.calls.length
    await app.tick()
    await app.login()
    assert.equal(app.timers.size, 0)
    assert.equal(app.button.disabled, true)
    assert.equal(app.calls.length, count)
    assert.equal(app.submissions.length, 0)
  } finally {
    config.config.revision = revision
  }
})
