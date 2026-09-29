// Runtime usage capture (prototype). Drives the app in a real browser and
// records which response fields the frontend actually reads, by wrapping each
// JSON response in a Proxy that logs property access. Over-fetch = fields
// returned but never read. Immune to minification and name transforms, because
// it watches the real access, not the source text.
//
// Instruments both fetch()/Response.json and XMLHttpRequest (Angular/HttpClient).
//
// Usage:
//   node runtime-capture.js BASE_URL [--gt FILE] [--user U --pass P]
//        [--routes '#/a,#/b']   (SPA hash routes to visit so their calls fire)

const { chromium } = require('playwright');
const fs = require('fs');

// Runs in the page before app code. Wraps JSON from fetch and XHR in a Proxy
// that records every field name read, and stashes the raw response by path.
function instrument() {
  window.__used = new Set();
  window.__responses = {};
  const isPlain = (v) => Array.isArray(v) || (v && Object.getPrototypeOf(v) === Object.prototype);
  const wrap = (obj) => {
    if (!isPlain(obj)) return obj;
    return new Proxy(obj, {
      get(target, prop, recv) {
        const val = Reflect.get(target, prop, recv);
        if (typeof prop === 'string' && prop !== 'then' && prop !== 'length' && !/^\d+$/.test(prop)) {
          window.__used.add(prop);
        }
        return isPlain(val) ? wrap(val) : val;
      },
    });
  };
  const stash = (url, data) => {
    try { window.__responses[new URL(url).pathname] = data; }
    catch (e) { window.__responses[url] = data; }
  };
  // fetch path
  const origJson = Response.prototype.json;
  Response.prototype.json = function () {
    const url = this.url;
    return origJson.call(this).then((data) => { stash(url, data); return wrap(data); });
  };
  // XHR path: capture raw JSON bodies on load (Angular reads responseText).
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener('load', () => {
      try {
        const ct = this.getResponseHeader('content-type') || '';
        if (ct.includes('json') && this.responseText) {
          stash(this.responseURL, JSON.parse(this.responseText));
        }
      } catch (e) { /* not json */ }
    });
    return origSend.apply(this, arguments);
  };
  // Usage tracking: Angular builds the body the component reads via JSON.parse,
  // so wrap its result. Non-API parses only make over-fetch more conservative.
  const origParse = JSON.parse;
  JSON.parse = function (text, reviver) {
    const data = origParse.call(JSON, text, reviver);
    return isPlain(data) ? wrap(data) : data;
  };
}

function walk(obj, out) {
  if (Array.isArray(obj)) {
    for (const it of obj) walk(it, out);
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === 'object') walk(v, out);
      else out.add(k);
    }
  }
}

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : def;
}

(async () => {
  const base = process.argv[2].replace(/\/$/, '');
  const gtPath = arg('--gt');
  const user = arg('--user');
  const pass = arg('--pass');
  const routes = (arg('--routes', '') || '').split(',').filter(Boolean);

  let token = null;
  if (user && pass) {
    const r = await fetch(base + '/rest/user/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: user, password: pass }),
    });
    token = (await r.json()).authentication.token;
    console.log('logged in, token captured');
  }

  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage();
  await page.addInitScript(instrument);
  if (token) await page.addInitScript((t) => localStorage.setItem('token', t), token);

  // networkidle is unreliable on apps with a persistent socket (Juice Shop),
  // so wait for the document then let the initial XHRs settle on a timer.
  await page.goto(base, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(3500);
  for (const route of routes) {
    await page.evaluate((h) => { location.hash = h; }, route);
    await page.waitForTimeout(2500);  // let the route's XHRs fire and settle
  }

  const cap = await page.evaluate(() => ({
    responses: window.__responses, used: Array.from(window.__used),
  }));
  await browser.close();

  // Only analyze real API responses. Static asset JSON (i18n dictionaries) and
  // config blobs are not per-record data and would flood the result.
  const apiPrefixes = (arg('--api', '/api,/rest')).split(',');
  const isApi = (ep) => apiPrefixes.some((p) => ep.startsWith(p)) && !ep.startsWith('/assets');

  const used = new Set(cap.used);
  const overFetch = [];
  for (const [ep, data] of Object.entries(cap.responses)) {
    if (!isApi(ep)) continue;
    const leaves = new Set();
    walk(data, leaves);
    for (const leaf of leaves) if (!used.has(leaf)) overFetch.push(`${ep}:${leaf}`);
  }
  overFetch.sort();

  console.log('endpoints:', Object.keys(cap.responses).length, ' over_fetch:', overFetch.length);
  console.log('over_fetch:', overFetch.join(', ') || 'none');
  fs.writeFileSync('capture.json', JSON.stringify(cap, null, 2));

  if (gtPath) {
    const gt = new Set(JSON.parse(fs.readFileSync(gtPath, 'utf8')).over_fetch);
    const found = new Set(overFetch);
    const tp = [...found].filter((x) => gt.has(x));
    console.log(`score over_fetch recall=${(tp.length / gt.size).toFixed(3)} precision=${(tp.length / (found.size || 1)).toFixed(3)}`);
    console.log('FN:', [...gt].filter((x) => !found.has(x)).join(', ') || 'none');
    console.log('FP:', [...found].filter((x) => !gt.has(x)).join(', ') || 'none');
  }
})();
