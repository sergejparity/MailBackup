// Browser test for issue #8: opening an HTML mail must not contact any remote
// server until "Load remote content" is clicked. Also checks (issue #10) that
// the UI itself loads nothing but the local server's files, and (issue #15)
// that downloads carry a single-use ticket instead of the API token.
//
// Needs Node 18+, Playwright and a Chromium for it, and a built server:
//   cargo build -p mailbackup-server
//   NODE_PATH="$(npm root -g)" node scripts/browser-tests/remote-content.mjs
//
// A local HTTP "tracker" stands in for the senders' servers and counts every
// TCP connection and request it gets. The fixture mail points remote images,
// CSS, fonts, srcset, meta refresh, <base> and resource hints at it.

import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import http from 'node:http';

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

// --- tracker -----------------------------------------------------------------
const tracker = { connections: 0, requests: [] };
const trackerServer = http.createServer((req, res) => {
  tracker.requests.push(req.url);
  if (req.url.endsWith('.css')) {
    res.writeHead(200, { 'content-type': 'text/css' });
    res.end('body { background: red; }');
  } else if (req.url.endsWith('.png')) {
    res.writeHead(200, { 'content-type': 'image/png' });
    res.end(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'));
  } else {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<p>tracked</p>');
  }
});
trackerServer.on('connection', () => tracker.connections++);
await new Promise((r) => trackerServer.listen(0, '127.0.0.1', r));
const trackerUrl = `http://127.0.0.1:${trackerServer.address().port}`;

// --- fixture and server ------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), 'mailbackup-browser-'));
const env = { ...process.env, HOME: dir, MAILBACKUP_KEYRING: 'none' };
const messageId = execFileSync(
  'cargo',
  ['run', '-q', '-p', 'mailbackup-core', '--example', 'seed_html_mail', '--', dir, trackerUrl],
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

// --- browser -----------------------------------------------------------------
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const pageRequests = [];
  page.on('request', (req) => pageRequests.push(req.url()));
  await page.goto(appUrl);
  await page.waitForFunction(() => typeof selectMessage === 'function');
  await page.evaluate(() => document.fonts.ready);

  // Issue #10: the UI itself only talks to the local server (bundled fonts)
  const external = pageRequests.filter((u) => !u.startsWith(appUrl) && !u.startsWith('data:'));
  check(external.length === 0, `loading the UI makes no external requests (got ${JSON.stringify(external)})`);
  const fontsOk = await page.evaluate(() =>
    ['400 12px "Plus Jakarta Sans"', '700 12px "Plus Jakarta Sans"', '400 12px "JetBrains Mono"'].every((f) => document.fonts.check(f)),
  );
  const fontLoads = pageRequests.filter((u) => u.includes('/fonts/') && u.endsWith('.woff2'));
  check(fontsOk && fontLoads.length > 0, `bundled fonts load from the server (${fontLoads.length} font files)`);
  tracker.connections = 0;
  tracker.requests = [];

  await page.evaluate((id) => selectMessage(id), messageId);
  await page.waitForFunction(() => document.getElementById('view-body-frame').srcdoc.length > 0);
  const frameHandle = await page.$('#view-body-frame');
  const frame = await frameHandle.contentFrame();
  await frame.waitForLoadState('load');
  await sleep(2500); // the mail's meta refresh fires after 1 s

  check(tracker.requests.length === 0, `no requests to the tracker by default (got ${JSON.stringify(tracker.requests)})`);
  check(tracker.connections === 0, `no connections to the tracker by default (got ${tracker.connections})`);
  check((await frameHandle.contentFrame()).url() === 'about:srcdoc', 'meta refresh did not navigate the frame');
  check((await page.getAttribute('#view-body-frame', 'sandbox')) === '', 'iframe sandbox has no permissions');
  check(await page.isVisible('#view-remote-banner'), 'the "remote content blocked" banner is shown');
  const cidWidth = await frame.$eval('#cid-img', (img) => img.naturalWidth).catch((e) => `error: ${e.message}`);
  check(cidWidth === 1, `inline cid: image renders from a data: URI (naturalWidth ${cidWidth})`);
  const srcdoc = await page.getAttribute('#view-body-frame', 'srcdoc');
  check(!/http-equiv="refresh"/i.test(srcdoc) && !/<base\b/i.test(srcdoc) && !/rel="(dns-prefetch|preconnect|prefetch)"/i.test(srcdoc),
    'refresh, <base> and resource hints are removed');

  await page.click('#btn-load-remote');
  await sleep(2500);
  const loaded = tracker.requests.map((u) => u.split('?')[0]);
  check(loaded.includes('/pixel.png'), `remote image loads after the click (${JSON.stringify(loaded)})`);
  check(loaded.includes('/bg.png'), 'remote CSS background loads after the click');
  check(!loaded.includes('/refresh') && !loaded.includes('/prefetch'), 'refresh and prefetch still never fire');
  check(!(await page.isVisible('#view-remote-banner')), 'the banner hides after loading remote content');
  check((await frameHandle.contentFrame()).url() === 'about:srcdoc', 'still no navigation after loading remote content');

  // Issue #15: a download link carries a one-time ticket, never the API token
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#btn-download-raw-eml')]);
  const downloadUrl = download.url();
  check(/[?&]ticket=[0-9a-f]{64}$/.test(downloadUrl) && !downloadUrl.includes('token='),
    `the .eml download URL has a ticket and no token (${downloadUrl})`);
  const saved = readFileSync(await download.path(), 'utf8');
  check(/^Subject:/m.test(saved), `the downloaded .eml arrives (${saved.length} bytes)`);
  const reuse = (await fetch(downloadUrl)).status;
  check(reuse === 401, `the ticket can't be used a second time (${reuse})`);
  const withToken = pageRequests.filter((u) => /[?&]token=/.test(u));
  check(withToken.length === 0, `no request URL carries the API token (${JSON.stringify(withToken)})`);
} finally {
  await browser.close();
  server.kill();
  trackerServer.close();
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log('\nall checks passed');
