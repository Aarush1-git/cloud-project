const $ = id => document.getElementById(id);
const BS = 1024 * 1024, ITER = 200000, enc = new TextEncoder();
const cfg = window.CONFIG || {};
const mock = new Map(); // used only when cfg.apiUrl is empty
const log = m => { $('log').textContent += m + '\n'; };
const b64 = u => btoa(String.fromCharCode(...u));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

$('mode').textContent = cfg.apiUrl ? 'Mode: LIVE (S3 + CloudFront)' : 'Mode: LOCAL MOCK (no cloud, data lost on refresh)';
$('mode').className = cfg.apiUrl ? 'live' : 'mock';

if (!window.crypto || !crypto.subtle) log('WARNING: Web Crypto needs HTTPS or localhost.');

async function keyFrom(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function put(key, data) {
  if (!cfg.apiUrl) { mock.set(key, data); return; }
  const r = await fetch(cfg.apiUrl, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passcode: cfg.passcode, key })
  });
  if (!r.ok) throw new Error('presign failed ' + r.status);
  const { url } = await r.json();
  const p = await fetch(url, { method: 'PUT', body: data });
  if (!p.ok) throw new Error('upload failed ' + p.status);
}

async function get(key) {
  if (!cfg.apiUrl) {
    if (!mock.has(key)) throw new Error('not found: ' + key);
    return mock.get(key);
  }
  const r = await fetch((cfg.baseUrl || '') + '/' + key);
  if (!r.ok) throw new Error(key + ' -> HTTP ' + r.status);
  return r.arrayBuffer();
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) { const k = i++; await fn(items[k], k); }
  }));
}
async function retry(fn, tries = 3) {
  for (let a = 1; ; a++) { try { return await fn(); } catch (e) { if (a >= tries) throw e; } }
}

// ZIP-START
const CRC_T = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = u => { let c = -1; for (let i = 0; i < u.length; i++) c = CRC_T[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
// Minimal uncompressed ZIP writer ("store" method), enough to bundle the encrypted blocks.
function zip(files) {
  const parts = [], cd = []; let off = 0;
  for (const f of files) {
    const nm = enc.encode(f.name), crc = crc32(f.data), sz = f.data.length;
    const h = new DataView(new ArrayBuffer(30));
    h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(12, 33, true);
    h.setUint32(14, crc, true); h.setUint32(18, sz, true); h.setUint32(22, sz, true); h.setUint16(26, nm.length, true);
    parts.push(h.buffer, nm, f.data);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(14, 33, true);
    c.setUint32(16, crc, true); c.setUint32(20, sz, true); c.setUint32(24, sz, true); c.setUint16(28, nm.length, true); c.setUint32(42, off, true);
    cd.push(c.buffer, nm);
    off += 30 + nm.length + sz;
  }
  let cdSize = 0; for (const p of cd) cdSize += p.byteLength;
  const e = new DataView(new ArrayBuffer(22));
  e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true);
  e.setUint32(12, cdSize, true); e.setUint32(16, off, true);
  return new Blob([...parts, ...cd, e.buffer], { type: 'application/zip' });
}
// ZIP-END

$('up').onclick = async () => {
  const f = $('file').files[0], pass = $('pass').value;
  if (!f || !pass) return alert('Pick a file and enter a passphrase');
  try {
    const id = crypto.randomUUID().slice(0, 8);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await keyFrom(pass, salt);
    const whole = await f.arrayBuffer();
    const sha = hex(await crypto.subtle.digest('SHA-256', whole));
    const n = Math.max(1, Math.ceil(f.size / BS));
    const blocks = [];
    log(`File "${f.name}" ${f.size} bytes -> ${n} block(s). SHA-256 ${sha.slice(0, 16)}...`);
    await pool([...Array(n).keys()], 4, async i => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: enc.encode(String(i)) },
        key, whole.slice(i * BS, (i + 1) * BS));
      const name = `block-${String(i).padStart(4, '0')}.enc`;
      await retry(() => put(`files/${id}/${name}`, ct));
      blocks[i] = { name, iv: b64(iv), size: ct.byteLength };
      log(`uploaded ${name} (${ct.byteLength} bytes, encrypted)`);
    });
    const manifest = { name: f.name, size: f.size, blockSize: BS, iterations: ITER, salt: b64(salt), sha256: sha, blocks };
    await retry(() => put(`files/${id}/manifest.json`, enc.encode(JSON.stringify(manifest)).buffer));
    log(`DONE. File ID: ${id}`);
    $('fid').value = id;
  } catch (e) { log('ERROR: ' + e.message); }
};

$('down').onclick = async () => {
  const id = $('fid').value.trim(), pass = $('pass2').value;
  if (!id || !pass) return alert('Enter file ID and passphrase');
  try {
    const m = JSON.parse(new TextDecoder().decode(await get(`files/${id}/manifest.json`)));
    const key = await keyFrom(pass, unb64(m.salt));
    const parts = [];
    await pool([...m.blocks.keys()], 4, async i => {
      const b = m.blocks[i];
      const ct = await retry(() => get(`files/${id}/${b.name}`));
      if (i === 0) log(`Downloaded block 0 as ciphertext, first 16 bytes: ${hex(ct.slice(0, 16))}`);
      parts[i] = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: unb64(b.iv), additionalData: enc.encode(String(i)) }, key, ct);
    });
    const blob = new Blob(parts);
    const ok = hex(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())) === m.sha256;
    log(ok ? `VERIFIED: "${m.name}" matches original hash.` : 'HASH MISMATCH: file corrupted.');
    const a = $('save');
    a.href = URL.createObjectURL(blob); a.download = m.name;
    a.textContent = 'Save ' + m.name; a.style.display = 'block';
  } catch (e) {
    log('ERROR: ' + (e.name === 'OperationError' ? 'decryption failed (wrong passphrase or tampered data)' : e.message));
  }
};

// Save the encrypted blocks exactly as stored in the cloud (no passphrase needed, nothing is decrypted).
$('rawdown').onclick = async () => {
  const id = $('fid').value.trim();
  if (!id) return alert('Enter the file ID');
  try {
    const mb = await get(`files/${id}/manifest.json`);
    const m = JSON.parse(new TextDecoder().decode(mb));
    const files = [{ name: 'manifest.json', data: new Uint8Array(mb) }];
    await pool([...m.blocks.keys()], 4, async i => {
      const b = m.blocks[i];
      files[i + 1] = { name: b.name, data: new Uint8Array(await retry(() => get(`files/${id}/${b.name}`))) };
    });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(zip(files)); a.download = `encrypted-${id}.zip`;
    document.body.appendChild(a); a.click(); a.remove();
    log(`Saved encrypted-${id}.zip: manifest + ${m.blocks.length} encrypted block(s). Unreadable without the passphrase.`);
  } catch (e) { log('ERROR: ' + e.message); }
};