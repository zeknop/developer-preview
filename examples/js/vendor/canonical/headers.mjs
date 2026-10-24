// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// RFC 5322 header block over RAW BYTES + the MIME parameter rules the v1.3
// manifest depends on (§9.2 boundary, §9.3 disposition/name, §9.4 filename).
//
// ONLY the header block is parsed, and the payload is never touched — the payload
// must stay the exact wire slice or an rfc822/binary leaf hash diverges from the
// signer's. Nothing in this file looks at a payload, and the header block is
// decoded to text only after it is cut off.
// ─────────────────────────────────────────────────────────────────────────────

import { base64ToBytes } from './digest.mjs';
import { singleByteEncoding, decodeSingleByte } from './single-byte.mjs';
import { multiByteEncoding, decodeMultiByte } from './multi-byte.mjs';

const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const utf8Lenient = new TextDecoder('utf-8', { fatal: false });
const latin1 = new TextDecoder('latin1');

/** Header bytes → text. 8-bit headers are UTF-8 in practice; latin-1 never throws. */
export function decodeHeaderBytes(bytes) {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return latin1.decode(bytes);
  }
}

/** Decode one RFC 2047 encoded-word payload. */
function decodeWordPayload(charset, encoding, text) {
  let bytes;
  if (encoding === 'b') {
    try {
      bytes = base64ToBytes(text);
    } catch {
      return null;
    }
  } else {
    const out = [];
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '_') { out.push(0x20); continue; }
      if (c === '=' && i + 2 < text.length && /^[0-9a-fA-F]{2}$/.test(text.slice(i + 1, i + 3))) {
        out.push(parseInt(text.slice(i + 1, i + 3), 16));
        i += 2;
        continue;
      }
      out.push(c.charCodeAt(0) & 0xff);
    }
    bytes = Uint8Array.from(out);
  }
  return decodeBytesWithCharset(bytes, charset);
}

/**
 * Bytes → text in `charset`. spec/canonical-content.md §2: the label names an
 * encoding of the WHATWG Encoding Standard and the bytes are read by that
 * encoding's decoder over the tables pinned in this repository; a label that
 * names no encoding, and no label at all, are read as UTF-8.
 *
 * The runtime's own TextDecoder is used for UTF-8 only, where it was measured
 * to agree with every other implementation. For the legacy encodings it does
 * not: node's is ICU, which puts unassigned Big5 and GBK pointers into the
 * private use area where the standard has an error, and refuses x-user-defined
 * and the replacement labels outright (measured by the publisher).
 */
export function decodeBytesWithCharset(bytes, charset) {
  const single = singleByteEncoding(charset);
  if (single) return decodeSingleByte(bytes, single);
  const multi = multiByteEncoding(charset);
  if (multi) return decodeMultiByte(bytes, multi);
  return utf8Lenient.decode(bytes);
}

const ENCODED_WORD = /=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g;

/**
 * spec §5: RFC 2047 encoded-words → Unicode. Adjacent encoded-words separated
 * only by whitespace join WITHOUT that whitespace (RFC 2047 §6.2) — the rule
 * the readers written in JavaScript apply through libmime and the readers written
 * in Python through decode_header. Plain text between words is preserved.
 */
export function decodeEncodedWords(value) {
  if (!value || value.indexOf('=?') === -1) return value || '';
  let out = '';
  let last = 0;
  let previousWasWord = false;
  ENCODED_WORD.lastIndex = 0;
  let m;
  while ((m = ENCODED_WORD.exec(value)) !== null) {
    const decoded = decodeWordPayload(m[1].split('*')[0], m[2].toLowerCase(), m[3]);
    if (decoded === null) { previousWasWord = false; continue; }
    const between = value.slice(last, m.index);
    if (!(previousWasWord && /^[ \t]*$/.test(between))) out += between;
    out += decoded;
    last = m.index + m[0].length;
    previousWasWord = true;
  }
  out += value.slice(last);
  return out;
}

/**
 * Cut the header block off the raw bytes and parse it.
 * Returns { headers: [{name, value}], bodyStart } with folded lines unfolded
 * (RFC 5322 §2.2.3: drop the CRLF, keep the folding whitespace).
 */
export function parseHeaderBlock(raw) {
  let sepStart = -1;
  let sepEnd = -1;
  for (let i = 0; i < raw.length; i++) {
    let j = i;
    if (raw[j] === 0x0d) j++;
    if (raw[j] !== 0x0a) continue;
    j++;
    if (raw[j] === 0x0d) j++;
    if (raw[j] !== 0x0a) continue;
    j++;
    sepStart = i;
    sepEnd = j;
    break;
  }
  const headerBytes = raw.subarray(0, sepStart === -1 ? raw.length : sepStart);
  const bodyStart = sepEnd === -1 ? raw.length : sepEnd;
  const text = decodeHeaderBytes(headerBytes);
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const headers = [];
  for (const line of lines) {
    if (!line) continue;
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += '\n' + line;
      continue;
    }
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1) });
  }
  return { headers, bodyStart };
}

/**
 * RFC 5322 §2.2.3 unfolding: delete the line break, KEEP the folding
 * whitespace — `Subject: Hello\r\n    World` unfolds to `Hello    World`,
 * which is byte-for-byte what Python's policy.default hands a reader in Python.
 */
function unfold(value) {
  return value.replace(/\r?\n/g, '').trim();
}

export function headerValues(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => unfold(h.value));
}

export function headerValue(headers, name) {
  const all = headerValues(headers, name);
  return all.length ? all[0] : null;
}

/** `type/subtype` of a Content-Type value, lowercased and stripped of params. */
function typeOf(value) {
  return String(value || '').split(';')[0].trim().toLowerCase();
}

/**
 * All parameters of a structured header value, with RFC 2231 continuations
 * (`name*0`, `name*1`) and charset-encoded values (`name*=utf-8''%C3%A1`)
 * collapsed, mirroring Python's collapse_rfc2231_value.
 */
export function headerParams(value) {
  const src = String(value || '');
  const raw = new Map();
  // Split on ';' outside quoted strings.
  const segments = [];
  let current = '';
  let inQuote = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '"' && src[i - 1] !== '\\') inQuote = !inQuote;
    if (c === ';' && !inQuote) { segments.push(current); current = ''; continue; }
    current += c;
  }
  segments.push(current);
  segments.shift(); // the type/disposition itself
  for (const segment of segments) {
    const eq = segment.indexOf('=');
    if (eq === -1) continue;
    const key = segment.slice(0, eq).trim().toLowerCase();
    let val = segment.slice(eq + 1).trim();
    if (val.startsWith('"')) val = val.slice(1, val.endsWith('"') ? -1 : undefined).replace(/\\(.)/g, '$1');
    raw.set(key, val);
  }
  const collapsed = new Map();
  const seen = new Set();
  for (const [key, val] of raw) {
    const m = key.match(/^([^*]+)(\*\d+)?(\*)?$/);
    if (!m) continue;
    const base = m[1];
    if (seen.has(base)) continue;
    if (!m[2] && !m[3]) { collapsed.set(base, val); seen.add(base); continue; }
    // RFC 2231: gather the numbered segments in order, then percent-decode.
    seen.add(base);
    let assembled = '';
    let charset = null;
    if (m[2]) {
      for (let i = 0; ; i++) {
        const plain = raw.get(`${base}*${i}`);
        const ext = raw.get(`${base}*${i}*`);
        const piece = ext !== undefined ? ext : plain;
        if (piece === undefined) break;
        if (i === 0 && ext !== undefined) {
          const parts = piece.split("'");
          if (parts.length >= 3) {
            charset = parts[0];
            assembled += percentDecode(parts.slice(2).join("'"), charset);
            continue;
          }
        }
        assembled += ext !== undefined ? percentDecode(piece, charset) : piece;
      }
    } else {
      const parts = val.split("'");
      assembled = parts.length >= 3 ? percentDecode(parts.slice(2).join("'"), parts[0]) : percentDecode(val, null);
    }
    collapsed.set(base, assembled);
  }
  return collapsed;
}

// ── §9.2a: the ONE reading of a boundary parameter ───────────────────────────
//
// One reading is normative, and §9.2a is it: the reading is the SIGNER's, because the
// signature covers the manifest the signer built. Reading a
// boundary the signer did not read means finding leaves the signature never covered.
// This is deliberately NOT headerParams(): a segment name with white space before its
// `=` is no segment to the signer, `*01` is not `*1`, and segment names group by exact
// case — three points where this file used to be more generous than the signer.
const ATTR_CHARS = new Set("!#$%&'+.^_`{|}~-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
const BOUNDARY_RE = /boundary\s*=\s*"([^"]+)"|boundary\s*=\s*"?([^";]+)"?/i;

/** Every RFC 2231 segment of `value`, as the signer's tokenizer finds them. */
function* parameterSegments(value) {
  const n = value.length;
  let i = 0;
  while (i < n) {
    const start = i;
    while (i < n && ATTR_CHARS.has(value[i])) i++;
    if (i <= start || i >= n || value[i] !== '*') {
      if (i === start) i++;
      continue;
    }
    const attribute = value.slice(start, i);
    i++;                                        // the mandatory '*'
    const digitsStart = i;
    while (i < n && value[i] >= '0' && value[i] <= '9') i++;
    const section = i > digitsStart ? value.slice(digitsStart, i) : '0';
    if (i < n && value[i] === '*') i++;         // the optional encoded flag
    if (i >= n || value[i] !== '=') continue;   // white space here = not a segment
    i++;
    let j = i;
    while (j < n && /\s/.test(value[j])) j++;
    let raw;
    if (j < n && value[j] === '"') {
      let k = j + 1;
      while (k < n) {
        if (value[k] === '\\') { k += 2; continue; }
        if (value[k] === '"') {
          raw = value.slice(j + 1, k);
          i = k + 1;
          if (i < n && value[i] === ';') i++;
          break;
        }
        k++;
      }
    }
    if (raw === undefined) {
      const valueStart = i;
      while (i < n && !/\s/.test(value[i])) i++;
      raw = value.slice(valueStart, i);
      if (raw.endsWith(';')) raw = raw.slice(0, -1);
    }
    yield { attribute, section, raw };
  }
}

/**
 * The boundary of a `multipart/*` container, or '' when the field carries none the
 * signer can use (§9.2a). '' means ONE opaque leaf, never a silent descend.
 */
export function usableBoundary(contentType) {
  const value = unfold(String(contentType || ''));
  const merged = new Map();     // attribute (exact case) → Map(section → text)
  const charsetOf = new Map();
  let curKey = '';
  let curLang = '';
  let curEnc = '';
  for (const { attribute, section, raw } of parameterSegments(value)) {
    let piece = raw;
    const lang = /^([^']*)'([^']*)'([\s\S]*)$/.exec(piece);
    if (lang) {
      if (attribute === curKey && lang[2] !== curLang) continue;
      curEnc = lang[1];
      curLang = lang[2];
      piece = lang[3];
    } else if (attribute !== curKey) {
      curEnc = '';
      curLang = '';
    }
    curKey = attribute;
    charsetOf.set(attribute, curEnc);
    if (!merged.has(attribute)) merged.set(attribute, new Map());
    merged.get(attribute).set(section, piece);
  }
  let augmented = value;
  for (const [attribute, sections] of merged) {
    let text = '';
    for (let index = 0; sections.has(String(index)); index++) text += sections.get(String(index));
    try { text = decodeURIComponent(text); } catch { /* the signer keeps the merged text */ }
    const charset = charsetOf.get(attribute);
    if (charset) text = percentDecode(encodeURIComponent(text), charset);
    augmented += ` ${attribute}="${text}";`;
  }
  const match = BOUNDARY_RE.exec(augmented);
  if (!match) return '';
  return (match[1] || match[2] || '').trim();
}

function percentDecode(text, charset) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '%' && /^[0-9a-fA-F]{2}$/.test(text.slice(i + 1, i + 3))) {
      out.push(parseInt(text.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      out.push(text.charCodeAt(i) & 0xff);
    }
  }
  return decodeBytesWithCharset(Uint8Array.from(out), charset || 'utf-8');
}

/** A parsed part header block, with the accessors mime_walk.py uses. */
export function partHeaders(headers) {
  const ctRaw = headerValue(headers, 'Content-Type');
  const cdRaw = headerValue(headers, 'Content-Disposition');
  const ctParams = headerParams(ctRaw);
  const cdParams = headerParams(cdRaw);
  let contentType = ctRaw ? typeOf(ctRaw) : 'text/plain';
  // Python's get_content_type(): a value that is not exactly type/subtype
  // falls back to the default type. Same fail-safe here.
  if ((contentType.match(/\//g) || []).length !== 1) contentType = 'text/plain';
  const disposition = cdRaw ? String(cdRaw).split(';')[0].trim().toLowerCase() : '';
  // §9.4 / Python get_filename(): Content-Disposition `filename` FIRST, then
  // Content-Type `name`. Never the other way round, never cross-header.
  let filename = cdParams.get('filename');
  if (filename === undefined) filename = ctParams.get('name');
  if (filename !== undefined) filename = decodeEncodedWords(filename);
  const contentId = headerValue(headers, 'Content-ID');
  return {
    contentType,
    disposition,
    filename: filename === undefined ? null : filename,
    contentId: contentId === null ? null : String(contentId),
    charset: ctParams.get('charset') || null,
    // §9.2a, ONE reading: the signer's, not this file's parameter rules.
    boundary: usableBoundary(ctRaw) || null,
    cte: (headerValue(headers, 'Content-Transfer-Encoding') || '').trim().toLowerCase(),
  };
}
