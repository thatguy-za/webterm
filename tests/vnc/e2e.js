const { chromium } = require('playwright');
// Opens real VNC servers through WebTerm in a real browser: the screens show up (noVNC draws them on a canvas).
// Run with tests/vnc/run.sh, which starts the servers.
const BASE = process.env.BASE || 'http://webterm:3000';
const OUT = process.env.OUT || '/work/out';
const dlg = () => page.locator('dialog[open]');
let page;
const results = [];
const step = async (name, fn) => { try { await fn(); results.push('ok   ' + name); } catch (e) { results.push('FAIL ' + name + ': ' + e.message.split('\n')[0]); try { await page.screenshot({ path: `${OUT}/FAIL-vnc-${name.replace(/\W+/g, '-')}.png` }); } catch (e2) { /* ignore */ } } };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ baseURL: BASE, viewport: { width: 1360, height: 840 }, colorScheme: 'dark' });
  page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/'); await page.waitForSelector('form');
  await page.fill('input[name=username]', 'owner'); await page.fill('input[name=password]', 'test-password-1234'); await page.fill('input[name=confirm]', 'test-password-1234');
  await page.click('button:has-text("Create account")'); await page.waitForSelector('input[name=saved]'); await page.check('input[name=saved]');
  await page.click('button:has-text("Continue")'); await page.waitForSelector('#shell');

  const add = async (name, port, user, password, address = 'tigervnc') => {
    await page.click('#add-host');
    await dlg().locator('select[name=protocol]').selectOption('vnc');
    await dlg().locator('input[name=name]').fill(name);
    await dlg().locator('input[name=address]').fill(address);
    if ((await dlg().locator('input[name=port]').inputValue()) !== '5900') throw new Error('the VNC default port is not 5900');
    await dlg().locator('input[name=port]').fill(String(port));
    if (user) await dlg().locator('input[name=username]').fill(user);
    await dlg().locator('input[name=password]').fill(password);
    await dlg().locator('button.primary').click();
    await page.waitForSelector('dialog[open]', { state: 'detached' });
  };
  const connected = async name => {
    await page.click(`.row.host:has-text("${name}") .row-main`);
    await page.waitForSelector('.pane:visible .vncscreen canvas', { timeout: 30000 });
    await page.waitForSelector('.tab.on .dot.live', { timeout: 30000 });
    // The desktop has really arrived: the canvas is the size of the remote screen, and not blank.
    const info = await page.locator('.pane:visible .vncscreen canvas').first().evaluate(c => ({ w: c.width, h: c.height }));
    if (!info.w || !info.h) throw new Error('the canvas is empty');
    return info;
  };

  await step('add VNC hosts', async () => {
    await add('vnc-password', 5900, '', 'raspberry');
    await add('vnc-tls', 5901, 'pi', 'raspberry');
    await add('vnc-wrong', 5900, '', 'wrongpass');
    await add('vnc-wayvnc', 5900, 'pi', 'raspberry', 'wayvnc');
    await add('vnc-wayvnc-wrong', 5900, 'pi', 'nope', 'wayvnc');
  });
  await step('VNC password login', async () => {
    const i = await connected('vnc-password');
    if (i.w !== 1024) throw new Error('unexpected screen size ' + i.w + 'x' + i.h);
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${OUT}/vnc-password.png` });
  });
  await step('TLS login with a username: certificate prompt, then the desktop', async () => {
    await page.click('.row.host:has-text("vnc-tls") .row-main');
    await page.waitForSelector('button:has-text("Trust and connect")', { timeout: 20000 });
    await page.screenshot({ path: `${OUT}/vnc-tls-trust.png` });
    const text = await page.locator('.tbox:visible').first().innerText();
    if (!/TLS certificate|SHA256:/.test(text)) throw new Error('the certificate prompt says: ' + text);
    await page.click('button:has-text("Trust and connect")');
    await page.waitForSelector('.pane:visible .vncscreen canvas', { timeout: 30000 });
    await page.waitForFunction(() => document.querySelector('.tab.on .dot.live'), null, { timeout: 30000 });
    const w = await page.locator('.pane:visible .vncscreen canvas').first().evaluate(c => c.width);
    if (w !== 800) throw new Error('unexpected screen width ' + w);
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${OUT}/vnc-tls.png` });
  });
  await step('a wrong password says so', async () => {
    await page.click('.row.host:has-text("vnc-wrong") .row-main');
    await page.locator('.tbox.danger:visible').waitFor({ timeout: 20000 });
    const text = await page.locator('.tbox.danger:visible').first().innerText();
    if (!/rejected|Authentication|password/i.test(text)) throw new Error('the error says: ' + text);
    await page.screenshot({ path: `${OUT}/vnc-wrong.png` });
  });
  await step('wayvnc, as on a Raspberry Pi: certificate prompt, then the desktop', async () => {
    await page.click('.row-main[aria-label="Open vnc-wayvnc"]');
    await page.waitForSelector('button:has-text("Trust and connect")', { timeout: 20000 });
    await page.screenshot({ path: `${OUT}/vnc-wayvnc-trust.png` });
    await page.click('button:has-text("Trust and connect")');
    await page.waitForSelector('.pane:visible .vncscreen canvas', { timeout: 30000 });
    const w = await page.locator('.pane:visible .vncscreen canvas').first().evaluate(c => c.width);
    if (w !== 1024) throw new Error('unexpected screen width ' + w);
    await page.waitForTimeout(2000);
    await page.screenshot({ path: `${OUT}/vnc-wayvnc.png` });
  });
  await step('wayvnc with a wrong password says so', async () => {
    await page.click('.row-main[aria-label="Open vnc-wayvnc-wrong"]');
    await page.waitForSelector('button:has-text("Trust and connect")', { timeout: 20000 }).then(() => page.click('button:has-text("Trust and connect")')).catch(() => {});
    await page.locator('.tbox.danger:visible').waitFor({ timeout: 20000 });
    const text = await page.locator('.tbox.danger:visible').first().innerText();
    if (!/rejected|Authentication|password|credentials/i.test(text)) throw new Error('the error says: ' + text);
  });
  await step('the second visit to the TLS server asks nothing', async () => {
    await page.click('.row.host:has-text("vnc-tls") .row-main');
    await page.waitForFunction(() => [...document.querySelectorAll('.tab')].filter(t => t.querySelector('.dot.live')).length >= 2, null, { timeout: 30000 });
    if (await page.locator('button:has-text("Trust and connect")').count()) throw new Error('a trusted certificate asked again');
  });

  console.log(results.join('\n'));
  console.log('page errors:', errors.length ? errors.slice(0, 5).join(' | ') : 'none');
  if (results.some(r => r.startsWith('FAIL')) || errors.length) process.exitCode = 1;
  await browser.close();
})().catch(e => { console.error('SCRIPT FAILED', e); process.exit(1); });
