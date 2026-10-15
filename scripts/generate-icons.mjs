// Generates raster favicons (apple-icon.png + favicon.ico) that mirror
// src/app/icon.svg. Run with: node scripts/generate-icons.mjs
//
// Pure Node (zlib) — no image dependencies. The SVG remains the source of
// truth for the design; keep the shapes below in sync if it changes.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// --- palette ---------------------------------------------------------------
const BG_A = [11, 18, 32]; // #0b1220
const BG_B = [16, 28, 48]; // #101c30
const BORDER = [51, 65, 85]; // #334155
const ACCENT = [56, 189, 248]; // #38bdf8
const GLASS_ALPHA = 0.12;

const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);
const lerp = (a, b, t) => a + (b - a) * t;

function inRoundRect(px, py, x, y, w, h, r) {
  if (px >= x + r && px <= x + w - r && py >= y && py <= y + h) return true;
  if (py >= y + r && py <= y + h - r && px >= x && px <= x + w) return true;
  const cx = clamp(px, x + r, x + w - r);
  const cy = clamp(py, y + r, y + h - r);
  const dx = px - cx;
  const dy = py - cy;
  return dx * dx + dy * dy <= r * r;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax;
  const vy = by - ay;
  const wx = px - ax;
  const wy = py - ay;
  const len2 = vx * vx + vy * vy;
  const t = len2 === 0 ? 0 : clamp((wx * vx + wy * vy) / len2, 0, 1);
  const dx = px - (ax + vx * t);
  const dy = py - (ay + vy * t);
  return Math.hypot(dx, dy);
}

// Sample a point in 64x64 design space -> [r,g,b,a] (a in 0..1).
function sample(px, py) {
  // Base: rounded panel with a diagonal gradient + border.
  const inPanel = inRoundRect(px, py, 2, 2, 60, 60, 14);
  const inBorder = inRoundRect(px, py, 1, 1, 62, 62, 15) && !inRoundRect(px, py, 3, 3, 58, 58, 13);
  if (!inPanel) return [0, 0, 0, 0];

  let [r, g, b] = BG_A;
  const t = clamp(((px - 2) / 60 + (py - 2) / 60) / 2, 0, 1);
  r = lerp(BG_A[0], BG_B[0], t);
  g = lerp(BG_A[1], BG_B[1], t);
  b = lerp(BG_A[2], BG_B[2], t);
  if (inBorder) [r, g, b] = BORDER;

  // Lens glass fill.
  const d = Math.hypot(px - 27, py - 27);
  if (d <= 12) {
    r = lerp(r, ACCENT[0], GLASS_ALPHA);
    g = lerp(g, ACCENT[1], GLASS_ALPHA);
    b = lerp(b, ACCENT[2], GLASS_ALPHA);
  }
  // Lens ring stroke (r=14, width 4 -> 12..16).
  if (d >= 12 && d <= 16) [r, g, b] = ACCENT;
  // Handle capsule (37.5,37.5)->(49,49), radius 2.5.
  if (distToSegment(px, py, 37.5, 37.5, 49, 49) <= 2.5) [r, g, b] = ACCENT;
  // Port dots.
  for (const [cx, cy] of [
    [21, 22],
    [31, 20],
    [25, 31],
    [33, 30],
  ]) {
    if (Math.hypot(px - cx, py - cy) <= 2.6) [r, g, b] = ACCENT;
  }
  return [r, g, b, 1];
}

/** Render an RGBA buffer at `size` with 4x4 supersampling. */
function render(size) {
  const out = Buffer.alloc(size * size * 4);
  const SS = 4;
  const step = 64 / size;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let ar = 0;
      let ag = 0;
      let ab = 0;
      let aa = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const px = (x + (sx + 0.5) / SS) * step;
          const py = (y + (sy + 0.5) / SS) * step;
          const [r, g, b, a] = sample(px, py);
          ar += r * a;
          ag += g * a;
          ab += b * a;
          aa += a;
        }
      }
      const n = SS * SS;
      const alpha = aa / n;
      const idx = (y * size + x) * 4;
      out[idx] = alpha > 0 ? Math.round(ar / aa) : 0;
      out[idx + 1] = alpha > 0 ? Math.round(ag / aa) : 0;
      out[idx + 2] = alpha > 0 ? Math.round(ab / aa) : 0;
      out[idx + 3] = Math.round(alpha * 255);
    }
  }
  return out;
}

// --- PNG ------------------------------------------------------------------
const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// --- ICO (PNG-compressed entries) -----------------------------------------
function encodeIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(entries.length, 4);
  const dir = Buffer.alloc(16 * entries.length);
  let offset = 6 + dir.length;
  const blobs = [];
  entries.forEach(({ size, png }, i) => {
    const e = i * 16;
    dir[e] = size >= 256 ? 0 : size;
    dir[e + 1] = size >= 256 ? 0 : size;
    dir[e + 2] = 0; // palette
    dir[e + 3] = 0;
    dir.writeUInt16LE(1, e + 4); // planes
    dir.writeUInt16LE(32, e + 6); // bpp
    dir.writeUInt32LE(png.length, e + 8);
    dir.writeUInt32LE(offset, e + 12);
    offset += png.length;
    blobs.push(png);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

// --- emit -----------------------------------------------------------------
const applePng = encodePng(180, render(180));
fs.writeFileSync(path.join(ROOT, 'src/app/apple-icon.png'), applePng);

const ico = encodeIco([16, 32, 48].map((size) => ({ size, png: encodePng(size, render(size)) })));
fs.writeFileSync(path.join(ROOT, 'public/favicon.ico'), ico);

console.log(`Wrote src/app/apple-icon.png (${applePng.length} bytes)`);
console.log(`Wrote public/favicon.ico (${ico.length} bytes)`);
