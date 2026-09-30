"""Browser-side usage instrumentation, shared by the crawler and the re-drive.

INSTRUMENT_JS wraps every JSON response (fetch + XHR) in a Proxy that records the
field names the app reads into window.__used, and stashes raw responses by path.
harvest() reads both back out of a page.
"""

INSTRUMENT_JS = r"""
(() => {
  window.__used = new Set();
  window.__responses = {};
  const origParse = JSON.parse;
  const isPlain = (v) => Array.isArray(v) || (v && Object.getPrototypeOf(v) === Object.prototype);
  const wrap = (obj) => {
    if (!isPlain(obj)) return obj;
    return new Proxy(obj, {
      get(t, prop, r) {
        const val = Reflect.get(t, prop, r);
        if (typeof prop === 'string' && prop !== 'then' && prop !== 'length' && !/^\d+$/.test(prop)) {
          window.__used.add(prop);
        }
        return isPlain(val) ? wrap(val) : val;
      },
    });
  };
  const stash = (u, data) => {
    try { window.__responses[new URL(u).pathname] = data; }
    catch (e) { window.__responses[u] = data; }
  };
  const origJson = Response.prototype.json;
  Response.prototype.json = function () {
    const u = this.url;
    return origJson.call(this).then((data) => { stash(u, data); return wrap(data); });
  };
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener('load', () => {
      try {
        const ct = this.getResponseHeader('content-type') || '';
        if (ct.includes('json') && this.responseText) stash(this.responseURL, origParse(this.responseText));
      } catch (e) { /* not json */ }
    });
    return origSend.apply(this, arguments);
  };
  JSON.parse = function (t, r) {
    const data = origParse.call(JSON, t, r);
    return isPlain(data) ? wrap(data) : data;
  };
})();
"""

def harvest(page):
    # Pull the recorded responses and read-field names off a page.
    cap = page.evaluate("() => ({responses: window.__responses, used: Array.from(window.__used)})")
    return cap.get("responses") or {}, cap.get("used") or []
