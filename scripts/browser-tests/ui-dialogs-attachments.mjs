// Browser test for issues #59, #60 and #61:
// - #60: a press inside the Settings / Export dialog released outside it (a
//   text selection dragged past the edge) leaves the dialog open; a click on
//   the backdrop still closes it.
// - #61: attachments in the message view download, decoded, under their
//   names, as downloads with a single-use ticket; an HTML attachment never
//   renders in the app.
// - #59: the script the tray's "Sync Now" runs in the window starts a sync of
//   every account, like the window's own Sync Now button.
// - #65: the desktop app's download folder and "ask every time" settings.
// - #66: the web access switch, as the headless server shows it.
//
// Needs Node 18+, Playwright and a Chromium for it, and a built server:
//   cargo build -p mailbackup-server
//   NODE_PATH="$(npm root -g)" node scripts/browser-tests/ui-dialogs-attachments.mjs

import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const root = resolve(new URL('../..', import.meta.url).pathname);
const serverBin = process.env.MAILBACKUP_SERVER_BIN || join(root, 'target/debug/mailbackup-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}`);
  if (!ok) failures.push(what);
};

// --- fixture and server ------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'mailbackup-browser-'));
const env = { ...process.env, HOME: dir, MAILBACKUP_KEYRING: 'none' };
const messageId = execFileSync(
  'cargo',
  ['run', '-q', '-p', 'mailbackup-core', '--example', 'seed_attachment_mail', '--', dir],
  { cwd: root, env, encoding: 'utf8' },
).trim();

const port = 20000 + Math.floor(Math.random() * 20000);
const server = spawn(serverBin, ['--port', String(port), '--config', join(dir, 'config.yaml')], { env, stdio: 'ignore' });
const appUrl = `http://127.0.0.1:${port}/`;
for (let i = 0; ; i++) {
  try {
    if ((await fetch(appUrl)).ok) break;
  } catch {}
  if (i > 100) throw new Error('server did not start');
  await sleep(100);
}

// A UTF-8 locale, or Chromium saves non-ASCII names (résumé.pdf) as "download"
const browser = await chromium.launch({ env: { ...process.env, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' } });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 840 }, acceptDownloads: true });
  const requests = [];
  page.on('request', (req) => requests.push(`${req.method()} ${new URL(req.url()).pathname}`));
  await page.goto(appUrl);
  await page.waitForFunction(() => typeof selectMessage === 'function' && state.accounts.length > 0);

  // --- #60: dialogs ----------------------------------------------------------
  const isOpen = (id) => page.$eval(`#${id}`, (m) => m.style.display === 'flex');
  // Drags from the middle of `fieldSel` to a backdrop point outside the card
  async function dragOut(fieldSel) {
    const box = await page.locator(fieldSel).boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2, 5, { steps: 10 });
    await page.mouse.move(5, 5, { steps: 10 });
    await page.mouse.up();
  }

  await page.click('#btn-open-settings');
  await page.waitForFunction(() => document.getElementById('settings-modal').style.display === 'flex');
  await page.click('#settings-modal .tab-btn[data-tab="tab-add"]');
  await page.fill('#form-name', 'Some text to select');
  await dragOut('#form-name');
  check(await isOpen('settings-modal'), 'Settings stays open after a selection drag released on the backdrop');
  await page.mouse.click(5, 5);
  check(!(await isOpen('settings-modal')), 'a click on the backdrop still closes Settings');

  await page.click('#btn-export-mbox-dialog');
  await page.waitForFunction(() => document.getElementById('export-modal').style.display === 'flex');
  await page.fill('#export-filename-input', 'a-long-file-name-to-select.mbox');
  await dragOut('#export-filename-input');
  check(await isOpen('export-modal'), 'Export stays open after a selection drag released on the backdrop');
  // A press on the backdrop released inside the dialog doesn't close it either
  const card = await page.locator('#export-modal .modal-card').boundingBox();
  await page.mouse.move(5, 5);
  await page.mouse.down();
  await page.mouse.move(card.x + card.width / 2, card.y + card.height / 2, { steps: 10 });
  await page.mouse.up();
  check(await isOpen('export-modal'), 'Export stays open after a press on the backdrop released inside it');
  await page.mouse.click(5, 5);
  check(!(await isOpen('export-modal')), 'a click on the backdrop still closes Export');

  // --- #61: attachments ------------------------------------------------------
  await page.evaluate((id) => selectMessage(id), messageId);
  await page.waitForFunction(() => document.querySelectorAll('#view-attachments-list .att-chip').length === 3);
  const chips = await page.$$eval('#view-attachments-list .att-chip', (cs) => cs.map((c) => [c.tagName, c.textContent.trim()]));
  check(chips.every(([tag]) => tag === 'BUTTON'), `attachments are buttons (${JSON.stringify(chips)})`);

  const expected = [
    ['attachment-1.png', (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))],
    ['page.html', (b) => b.toString().startsWith('<script>')],
    ['résumé.pdf', (b) => b.toString('latin1').startsWith('%PDF-1.4')],
  ];
  const titleBefore = await page.title();
  for (const [i, [name, bytesOk]] of expected.entries()) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.click(`#view-attachments-list .att-chip:nth-child(${i + 1})`),
    ]);
    const url = download.url();
    const body = readFileSync(await download.path());
    check(download.suggestedFilename() === name, `attachment ${i + 1} downloads as ${name} (got ${download.suggestedFilename()})`);
    check(bytesOk(body), `attachment ${i + 1} arrives decoded (${body.length} bytes)`);
    check(/[?&]ticket=[0-9a-f]{64}$/.test(url) && !url.includes('token='), `attachment ${i + 1} uses a ticket (${url})`);
    check((await fetch(url)).status === 401, `attachment ${i + 1}'s ticket works only once`);
  }
  check(page.url() === appUrl && (await page.title()) === titleBefore, 'the HTML attachment did not render in the app');

  // --- #65: download settings ------------------------------------------------
  await page.click('#btn-open-settings');
  await page.click('#settings-modal .tab-btn[data-tab="tab-settings"]');
  await page.waitForFunction(() => document.getElementById('settings-download-dir').value !== '');
  const defaultDir = await page.inputValue('#settings-download-dir');
  check(await page.isDisabled('#btn-reset-download-dir'), `the default folder is shown (${defaultDir}) with nothing to reset`);
  check(!(await page.isChecked('#settings-ask-download')), '"Ask where to save" is off by default');
  await page.click('#settings-ask-download');
  await page.waitForFunction(() => document.getElementById('toast-message').textContent.includes('ask where'));
  let saved = await page.evaluate(async () => (await (await fetch('/api/settings')).json()));
  check(saved.ask_download_location === true, '"Ask where to save" is saved when ticked');
  // A folder outside the allowed locations is refused by the server
  const refused = await page.evaluate(async () =>
    (await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ download_dir: '/etc' }) })).status);
  check(refused === 400, `a folder outside the allowed locations is refused (${refused})`);
  // The home folder is allowed; the card shows it after a reload of Settings
  await page.evaluate(async (home) => {
    await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ download_dir: home }) });
    await loadSettings();
  }, dir);
  check((await page.inputValue('#settings-download-dir')).endsWith(dir.split('/').pop()) && !(await page.isDisabled('#btn-reset-download-dir')),
    `a chosen folder is shown (${await page.inputValue('#settings-download-dir')}) and can be reset`);
  await page.click('#btn-reset-download-dir');
  await page.waitForFunction((d) => document.getElementById('settings-download-dir').value === d, defaultDir);
  saved = await page.evaluate(async () => (await (await fetch('/api/settings')).json()));
  check(saved.download_dir === '', '"Use Downloads folder" resets it');
  await page.click('#settings-ask-download');

  // --- #66: web access, as the headless server (always listening) shows it --
  const web = await page.evaluate(() => ({
    checked: document.getElementById('settings-web-server').checked,
    disabled: document.getElementById('settings-web-server').disabled,
    status: document.getElementById('web-server-status').textContent,
    note: document.getElementById('web-server-note').textContent,
  }));
  check(web.checked && web.disabled && web.status === 'On' && /background service/.test(web.note),
    `the headless server shows web access as always on (${JSON.stringify(web)})`);
  await page.keyboard.press('Escape');

  // --- #59: what the tray's Sync Now runs ------------------------------------
  const before = requests.length;
  await page.evaluate("document.getElementById('btn-sync-all')?.click()");
  await page.waitForFunction(() => document.getElementById('btn-sync-all').disabled);
  await sleep(500);
  const syncs = requests.slice(before).filter((r) => r.startsWith('POST /api/sync/'));
  check(syncs.length === 1 && syncs[0] === 'POST /api/sync/acc', `the tray script starts a sync of each account (${JSON.stringify(syncs)})`);
} finally {
  await browser.close();
  server.kill();
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log('\nall checks passed');
