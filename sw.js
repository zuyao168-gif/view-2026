// 素材通道：页面请求 photos/ 下的照片、全景、视频时，到 a/ 取对应的密文，在浏览器里解密后交给页面。钥匙由入口页交来，存在本机浏览器里，不上传。
const VER = 'v1', SCOPE = new URL(self.registration.scope).pathname, DB = 'sv:' + SCOPE, STORE = 'k'        // 库名带上本站的路径：同一个域名下别的站点不会互相覆盖
const TYPES = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', mp4: 'video/mp4', json: 'application/json' }
let AK = null, KEY = null, EXP = 0                                  // EXP：限时链接交来的钥匙到什么时候为止（毫秒；0 表示不限时）
const mem = new Map(); let memSize = 0; const MEM_MAX = 160 * 1048576        // 视频要按片段反复取，解密后的整段先留在内存里

const b64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u }
const idb = () => new Promise((res, rej) => { const r = indexedDB.open(DB, 1); r.onupgradeneeded = () => r.result.createObjectStore(STORE); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error) })
const put = async v => { const d = await idb(); await new Promise((res, rej) => { const t = d.transaction(STORE, 'readwrite'); t.objectStore(STORE).put(v, 'ak'); t.oncomplete = res; t.onerror = () => rej(t.error) }); d.close() }
const del = async () => { const d = await idb(); await new Promise((res, rej) => { const t = d.transaction(STORE, 'readwrite'); t.objectStore(STORE).delete('ak'); t.oncomplete = res; t.onerror = () => rej(t.error) }); d.close() }
const get = async () => { const d = await idb(); const v = await new Promise((res, rej) => { const q = d.transaction(STORE).objectStore(STORE).get('ak'); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error) }); d.close(); return v }
async function setKey(ak, exp) { if (!(ak === AK && KEY)) { KEY = await crypto.subtle.importKey('raw', b64(ak), 'AES-GCM', false, ['decrypt']); AK = ak; mem.clear(); memSize = 0 } EXP = +exp || 0 }
async function nameOf(rel) { const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(VER + '|' + AK + '|' + rel))); let s = ''; for (let i = 0; i < 20; i++) s += h[i].toString(16).padStart(2, '0'); return s }

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()))
self.addEventListener('message', e => {
  if (e.data && e.data.t === 'wipe') { e.waitUntil((async () => { KEY = null; AK = null; EXP = 0; mem.clear(); memSize = 0; try { await del() } catch (_) { } })()); return }   // 入口页说授权没了：把本机存的照片钥匙删掉
  if (!e.data || e.data.t !== 'key' || typeof e.data.ak !== 'string') return
  e.waitUntil((async () => { await setKey(e.data.ak, e.data.exp); try { await put({ ak: e.data.ak, exp: +e.data.exp || 0 }) } catch (_) { } if (e.ports[0]) e.ports[0].postMessage('ok') })())
})
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url); if (u.origin !== self.location.origin || e.request.method !== 'GET' || !u.pathname.startsWith(SCOPE)) return
  let rel; try { rel = decodeURIComponent(u.pathname.slice(SCOPE.length)) } catch (_) { return }
  if (!rel.startsWith('photos/')) return
  e.respondWith(serve(e.request, rel))
})

async function serve(req, rel) {
  try {
    if (!KEY) { const v = await get().catch(() => null), o = typeof v === 'string' ? { ak: v, exp: 0 } : v; if (!o || !o.ak) return new Response('locked', { status: 403 }); await setKey(o.ak, o.exp) }   // 浏览器把本通道休眠过，钥匙从本机取回（早先存的是一个字符串）
    if (EXP && Date.now() > EXP) { KEY = null; AK = null; EXP = 0; mem.clear(); memSize = 0; try { await del() } catch (_) { } return new Response('expired', { status: 403 }) }   // 限时链接到期：钥匙作废并从本机删掉
    let buf = mem.get(rel)
    if (!buf) {
      const r = await fetch(SCOPE + 'a/' + await nameOf(rel) + '.bin'); if (!r.ok) return new Response('not found', { status: 404 })
      const c = new Uint8Array(await r.arrayBuffer()); buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.subarray(0, 12) }, KEY, c.subarray(12))
      if (/\.mp4$/i.test(rel) && buf.byteLength < MEM_MAX) { while (memSize + buf.byteLength > MEM_MAX && mem.size) { const k = mem.keys().next().value; memSize -= mem.get(k).byteLength; mem.delete(k) } mem.set(rel, buf); memSize += buf.byteLength }
    }
    const type = TYPES[(rel.split('.').pop() || '').toLowerCase()] || 'application/octet-stream', n = buf.byteLength, h = { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' }
    const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get('range') || '')
    if (m && (m[1] || m[2])) {
      let a = m[1] ? +m[1] : Math.max(0, n - +m[2]), b = m[1] && m[2] ? Math.min(+m[2], n - 1) : n - 1
      if (a >= n || a > b) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + n } })
      return new Response(buf.slice(a, b + 1), { status: 206, headers: Object.assign(h, { 'Content-Range': 'bytes ' + a + '-' + b + '/' + n, 'Content-Length': String(b - a + 1) }) })
    }
    return new Response(buf, { status: 200, headers: Object.assign(h, { 'Content-Length': String(n) }) })
  } catch (_) { return new Response('error', { status: 500 }) }
}
