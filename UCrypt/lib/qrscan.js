/**
 * UCrypt — QR scan-from-image adapter (R97 §4; the headline surface).
 * R104 (F-R104-QR-1): the DECODE LADDER — the CEO dropped the origin's own
 * downloaded QR PNG and the single-pass decode refused it. Measured repro
 * (tools/scratch/repro-qr.mjs): 3/14 real-world variants broke the one
 * attempt — INVERTED images (dark-mode renders/re-saves), tiny exports, and
 * noise-damaged files. The ladder re-runs the same vetted decoder across
 * transforms, cheapest-first, and reports which attempt landed.
 *
 * LAW 0.17 (vetted-vendor): the decoder is the vendored @paulmillr/qr
 * reader (MIT selected from its Apache-2.0 OR MIT dual license) — vetted,
 * bundled, size-bounded and reviewed in docs/vendoring/qr-reader-vetting.md.
 * The ladder adds NO vendor code and NO eval — every transform is local
 * pixel math on the already-capped image. The vendored file loads LAZY on
 * first scan (the R30-F1 corpus lesson: the popup's most-opened path never
 * pays for a rare feature).
 *
 * INPUTS (the order's scope): a pasted image (clipboard), a picked file, or
 * a drag-and-drop file. CAMERA CAPTURE IS OUT OF SCOPE — the vendored graph
 * contains no camera code by construction (dom.js is excluded).
 *
 * EVERY result is TYPED — the surfaces translate codes into localized,
 * actionable refusals (the 0.13 law: a failure names the fix):
 *   ok:true  { text, attempt }             — a QR was read (attempt = the
 *                                            ladder index that landed)
 *   ok:false { code: 'not-image' | 'too-large' | 'unreadable' | 'no-qr' | 'error' }
 *
 * BOUNDS (published): an image larger than MAX_IMAGE_BYTES is refused with
 * a typed reason before any decode; a larger-than-MAX_DIMENSION image is
 * downscaled to the bound before decode (a phone photo is fine, a hostile
 * decompression bomb is capped). The ladder is bounded: at most
 * LADDER_MAX_ATTEMPTS decode passes, each on at most MAX_DIMENSION² pixels.
 */
(function () {
  'use strict'

  const MAX_IMAGE_BYTES = 8 * 1024 * 1024 // 8 MB — a generous screenshot/photo bound
  const MAX_DIMENSION = 4096 // per-axis cap before decode (downscale, never crop)
  const LADDER_MAX_ATTEMPTS = 10 // the bounded worst case (law: bounded CPU per scan)

  let decoderLoading = null

  function loadDecoder() {
    if (globalThis.UCryptQrReader) return Promise.resolve(globalThis.UCryptQrReader)
    if (!decoderLoading) {
      decoderLoading = new Promise((resolve, reject) => {
        try {
          const s = document.createElement('script')
          s.src = chrome.runtime.getURL('lib/vendor/qr-reader.js')
          s.onload = () => {
            if (globalThis.UCryptQrReader) resolve(globalThis.UCryptQrReader)
            else { decoderLoading = null; reject(new Error('decoder did not initialize')) }
          }
          s.onerror = () => { decoderLoading = null; reject(new Error('decoder unavailable')) }
          document.head.appendChild(s)
        } catch (e) {
          decoderLoading = null
          reject(e)
        }
      })
    }
    return decoderLoading
  }

  // ── the ladder's pure pixel core (battery-pinned in r104-qr-ladder) ────────

  const clonePix = (im) => ({ data: new Uint8ClampedArray(im.data), width: im.width, height: im.height })

  /** Attempt 2 — color inversion (dark-mode renders/re-saves). */
  function invertPix(im) {
    const o = clonePix(im)
    for (let i = 0; i < o.data.length; i += 4) {
      o.data[i] = 255 - o.data[i]
      o.data[i + 1] = 255 - o.data[i + 1]
      o.data[i + 2] = 255 - o.data[i + 2]
    }
    return o
  }

  /** Otsu's global threshold over luma — the dim/low-contrast repair. */
  function otsuThreshold(im) {
    const hist = new Float64Array(256)
    const d = im.data
    for (let i = 0; i < d.length; i += 4) hist[Math.round(0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2])]++
    const total = d.length / 4
    let sum = 0
    for (let t = 0; t < 256; t++) sum += t * hist[t]
    let sumB = 0, wB = 0, best = 0, thr = 127
    for (let t = 0; t < 256; t++) {
      wB += hist[t]
      if (!wB) continue
      const wF = total - wB
      if (!wF) break
      sumB += t * hist[t]
      const mB = sumB / wB, mF = (sum - sumB) / wF
      const between = wB * wF * (mB - mF) * (mB - mF)
      if (between > best) { best = between; thr = t }
    }
    return thr
  }

  /** Attempt 3/4 — hard binarize at the Otsu threshold (both polarities). */
  function binarizePix(im, inverted) {
    const thr = otsuThreshold(im)
    const o = clonePix(im)
    for (let i = 0; i < o.data.length; i += 4) {
      const l = 0.299 * o.data[i] + 0.587 * o.data[i + 1] + 0.114 * o.data[i + 2]
      const dark = inverted ? l > thr : l <= thr
      const v = dark ? 0 : 255
      o.data[i] = o.data[i + 1] = o.data[i + 2] = v
    }
    return o
  }

  /** Attempt 5/6/9/10 — bilinear upscale (tiny/aliased exports — smoothing
   * rebuilds the module grid; nearest-neighbor only reproduces the aliasing). */
  function upscalePix(im, f) {
    const { width: W, height: H } = im
    const W2 = Math.round(W * f), H2 = Math.round(H * f)
    if (W2 > MAX_DIMENSION || H2 > MAX_DIMENSION) return null
    const out = new Uint8ClampedArray(W2 * H2 * 4)
    for (let y = 0; y < H2; y++) {
      const gy = (y + 0.5) / f - 0.5
      const y0 = Math.max(0, Math.min(H - 1, Math.floor(gy)))
      const y1 = Math.min(H - 1, y0 + 1)
      const fy = Math.max(0, Math.min(1, gy - y0))
      for (let x = 0; x < W2; x++) {
        const gx = (x + 0.5) / f - 0.5
        const x0 = Math.max(0, Math.min(W - 1, Math.floor(gx)))
        const x1 = Math.min(W - 1, x0 + 1)
        const fx = Math.max(0, Math.min(1, gx - x0))
        const di = (y * W2 + x) * 4
        for (let c = 0; c < 3; c++) {
          const p00 = im.data[(y0 * W + x0) * 4 + c], p10 = im.data[(y0 * W + x1) * 4 + c]
          const p01 = im.data[(y1 * W + x0) * 4 + c], p11 = im.data[(y1 * W + x1) * 4 + c]
          out[di + c] = (p00 * (1 - fx) + p10 * fx) * (1 - fy) + (p01 * (1 - fx) + p11 * fx) * fy
        }
        out[di + 3] = 255
      }
    }
    return { data: out, width: W2, height: H2 }
  }

  /** Attempt — 3×3 median denoise (salt-and-pepper / JPEG impulse damage;
   * the classic removal filter, one luma pass, edges preserved). */
  function medianPix(im) {
    const { width: W, height: H } = im
    const out = new Uint8ClampedArray(im.data)
    const win = new Float64Array(9)
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        let n = 0
        for (let dy = -1; dy <= 1; dy++) {
          const yy = Math.max(0, Math.min(H - 1, y + dy))
          for (let dx = -1; dx <= 1; dx++) {
            const xx = Math.max(0, Math.min(W - 1, x + dx))
            const i = (yy * W + xx) * 4
            win[n++] = 0.299 * im.data[i] + 0.587 * im.data[i + 1] + 0.114 * im.data[i + 2]
          }
        }
        // insertion-sort the 9 samples (tiny, fixed) and take the median
        for (let a = 1; a < 9; a++) { const v = win[a]; let b = a - 1; while (b >= 0 && win[b] > v) { win[b + 1] = win[b]; b-- } win[b + 1] = v }
        const l = win[4]
        const di = (y * W + x) * 4
        out[di] = out[di + 1] = out[di + 2] = l
      }
    }
    return { data: out, width: W, height: H }
  }

  /** Attempt 7/8 — quiet-zone pad (a tight crop that ate the border). */
  function padPix(im, frac, inverted) {
    const { width: W, height: H } = im
    const m = Math.max(4, Math.round(Math.max(W, H) * frac))
    const W2 = W + 2 * m, H2 = H + 2 * m
    if (W2 > MAX_DIMENSION || H2 > MAX_DIMENSION) return null
    const fill = inverted ? 0 : 255
    const out = new Uint8ClampedArray(W2 * H2 * 4).fill(fill)
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
      const di = ((y + m) * W2 + (x + m)) * 4, si = (y * W + x) * 4
      out[di] = im.data[si]
      out[di + 1] = im.data[si + 1]
      out[di + 2] = im.data[si + 2]
      out[di + 3] = 255
    }
    return { data: out, width: W2, height: H2 }
  }

  /** Attempt — nearest-neighbor downscale (R106 F-R106-QR-3 residual class:
   * unlucky data patterns can fool the reader's finder/alignment heuristics
   * even on a pure-binary matrix; a resample at a different phase re-grids
   * the binarizer's blocks and escapes the trap. Bounded like upscale.) */
  function downscalePix(im, f) {
    const { width: W, height: H } = im
    const W2 = Math.max(1, Math.round(W * f)), H2 = Math.max(1, Math.round(H * f))
    const out = new Uint8ClampedArray(W2 * H2 * 4)
    for (let y = 0; y < H2; y++) {
      const sy = Math.min(H - 1, Math.floor(y / f))
      for (let x = 0; x < W2; x++) {
        const sx = Math.min(W - 1, Math.floor(x / f))
        const di = (y * W2 + x) * 4, si = (sy * W + sx) * 4
        out[di] = im.data[si]
        out[di + 1] = im.data[si + 1]
        out[di + 2] = im.data[si + 2]
        out[di + 3] = 255
      }
    }
    return { data: out, width: W2, height: H2 }
  }

  /**
   * THE LADDER (pure): the ordered transforms, each one decode() pass.
   * Natural first (the proven path), then the repairs the repro demanded:
   * inversion, both Otsu polarities, the upscales for tiny exports, the
   * quiet-zone pads for tight crops, and (R106) the downscales for the
   * finder-trap residual class. Bounded by LADDER_MAX_ATTEMPTS.
   * R106: each rung carries a NAME — the per-rung telemetry lands in the
   * diagnostics ring (rung numbers + fixed names only, NEVER decoded text —
   * law 0.22b), so an owner-side failure names the rung it died on.
   */
  function ladderTransforms(im) {
    const list = [{ name: 'natural', im }]
    const push = (name, x) => { if (x && list.length < LADDER_MAX_ATTEMPTS) list.push({ name, im: x }) }
    push('invert', invertPix(im))
    push('median', medianPix(im)) // impulse-noise repair (then the decode sees clean modules)
    push('binarize-median', binarizePix(medianPix(im), false)) // denoise + hard threshold
    push('binarize-inverted', binarizePix(im, true))
    push('pad-light', padPix(im, 0.08, false))
    if (Math.max(im.width, im.height) < 300) {
      // small renders keep the R104 tiny/crop focus: upscales + both pads
      push('upscale2', upscalePix(im, 2))
      push('upscale3', upscalePix(im, 3))
      push('pad-dark', padPix(im, 0.08, true))
      push('pad-light2', padPix(im, 0.16, false))
    } else {
      // R106 (F-R106-QR-3): THE FINDER-TRAP ESCAPES — unlucky periodic data
      // patterns fool the reader's heuristics on a perfect matrix; a
      // resample at a DIFFERENT PHASE re-grids the binarizer's blocks. The
      // factors are the measured spread over the mapped classes: the /u/
      // carriers (0.9), the v12/v14 finder traps (0.7), and the
      // %2F-periodic query URLs at display-render phases (0.85). Bounded:
      // the list caps at 10 rungs. (The polarity pads stay covered by the
      // invert + binarize-inverted rungs; tiny exports are the small branch.)
      push('downscale0.9', downscalePix(im, 0.9))
      push('downscale0.85', downscalePix(im, 0.85))
      push('downscale0.8', downscalePix(im, 0.8))
      push('downscale0.7', downscalePix(im, 0.7))
    }
    return list
  }

  /** Decode one ImageData-like ({data,width,height}) through the ladder. */
  async function decodeImageData(im) {
    if (!im || !im.width || !im.height || !im.data) return recordRing({ ok: false, code: 'unreadable' })
    let decode
    try {
      decode = await loadDecoder()
    } catch {
      return recordRing({ ok: false, code: 'error' })
    }
    const attempts = ladderTransforms(im)
    const rungs = []
    for (let i = 0; i < attempts.length; i++) {
      const a = attempts[i]
      let text = null
      try {
        const out = decode({ data: a.im.data, width: a.im.width, height: a.im.height })
        if (typeof out === 'string' && out) text = out
      } catch {
        text = null // no QR for this transform — try the next rung
      }
      // R106 telemetry: the rung's name + outcome only — never the text (0.22b)
      rungs.push({ rung: i + 1, name: a.name, ok: !!text })
      if (text) return recordRing({ ok: true, text, width: a.im.width, height: a.im.height, attempt: i + 1, attempts: attempts.length, rungs })
    }
    return recordRing({ ok: false, code: 'no-qr', attempts: attempts.length, rungs })
  }

  /**
   * R105 §2.2 — THE DIAGNOSTICS RING: the LAST decode outcome (rung NUMBERS
   * only — NEVER the decoded text) persisted to chrome.storage.session so
   * Help > Export diagnostics can report the QR decode-ladder's last landing
   * rung after a page navigation. Best-effort by law: the ring never blocks
   * or alters the decode path, and dies honestly where storage.session is
   * unavailable (non-extension contexts).
   */
  function recordRing(res) {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) return res
      const row = {
        outcome: res && res.ok ? 'ok' : String((res && res.code) || 'error'),
        attempt: res && typeof res.attempt === 'number' ? res.attempt : 0,
        attempts: res && typeof res.attempts === 'number' ? res.attempts : 0,
        // R106: the per-rung telemetry (rung number, fixed name, boolean —
        // never the decoded text). Bounded by the ladder's own cap.
        rungs: Array.isArray(res && res.rungs) ? res.rungs.slice(0, LADDER_MAX_ATTEMPTS) : [],
        at: Date.now(),
      }
      const p = chrome.storage.session.set({ 'ucrypt:qr:lastDecode': row })
      if (p && typeof p.catch === 'function') p.catch(() => {}) // best-effort
    } catch { /* the ring is best-effort — never blocks the decode path */ }
    return res
  }

  /** Decode an <img> (already loaded) or a canvas — rasterize, then ladder. */
  async function decodeFromImage(img) {
    const w = img.naturalWidth || img.width
    const h = img.naturalHeight || img.height
    if (!w || !h) return { ok: false, code: 'unreadable' }
    const scale = Math.min(1, MAX_DIMENSION / Math.max(w, h))
    const cw = Math.max(1, Math.round(w * scale))
    const ch = Math.max(1, Math.round(h * scale))
    let data
    try {
      const canvas = document.createElement('canvas')
      canvas.width = cw
      canvas.height = ch
      const ctx = canvas.getContext('2d', { willReadFrequently: true })
      if (!ctx) return { ok: false, code: 'unreadable' }
      ctx.drawImage(img, 0, 0, cw, ch)
      data = ctx.getImageData(0, 0, cw, ch)
    } catch {
      return { ok: false, code: 'unreadable' }
    }
    return decodeImageData({ data: data.data, width: cw, height: ch })
  }

  /**
   * R106 (F-R106-QR-2 fix) — THE MAGIC SNIFF (pure): the typed refusal only
   * when the bytes are CLEARLY not a common image. A Windows/Explorer drag
   * can hand the zone a File typed application/octet-stream (or empty) while
   * carrying real PNG/JPEG bytes — the old type-regex refused those with
   * not-image before the ladder ever ran (a dead end on the owner's path).
   * Battery-pinned in r106-qr-export.
   */
  function imageMagicFromBytes(bytes) {
    const b = bytes && bytes.length >= 12 ? bytes : null
    if (!b) return null
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png'
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpeg'
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'gif'
    if (b[0] === 0x42 && b[1] === 0x4d) return 'bmp'
    if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'webp'
    return null
  }

  /** Decode a Blob/File picked, pasted, or dropped by the user. */
  async function decodeFromBlob(blob) {
    if (!blob || !blob.size) return recordRing({ ok: false, code: 'not-image' })
    // R106: the type regex OR the magic accepts; a clearly-non-image blob is
    // still refused typed BEFORE any decode.
    let magic = null
    try {
      magic = imageMagicFromBytes(new Uint8Array(await blob.slice(0, 12).arrayBuffer()))
    } catch { magic = null }
    const typeOk = !blob.type || /^image\//.test(blob.type)
    if (!typeOk && !magic) return recordRing({ ok: false, code: 'not-image' })
    if (blob.size > MAX_IMAGE_BYTES) return recordRing({ ok: false, code: 'too-large' })
    const url = URL.createObjectURL(blob)
    try {
      const img = await new Promise((resolve, reject) => {
        const el = new Image()
        el.onload = () => resolve(el)
        el.onerror = () => reject(new Error('unreadable'))
        el.src = url
      })
      return await decodeFromImage(img)
    } catch (e) {
      return { ok: false, code: e && e.message === 'unreadable' ? 'unreadable' : 'error' }
    } finally {
      URL.revokeObjectURL(url)
    }
  }

  /**
   * THE DROP DEAD-END REPAIR (F-R104-QR-1, the second half): a drag that
   * carries an IMAGE URL instead of a File (dragging a picture from a web
   * page) used to be a SILENT no-op — the 0.13 law forbids dead ends. The
   * pure helper below extracts the candidate URL from the drop payload;
   * the surface fetches it (http/https only, the CSP's own scheme set) and
   * runs the SAME ladder. Returns null when nothing usable is carried.
   */
  function pickDropUrl({ uriList, html }) {
    const uri = String(uriList || '').split(/\r?\n/).map((s) => s.trim()).find((s) => /^https?:\/\//i.test(s))
    if (uri) return uri
    const m = String(html || '').match(/<img[^>]*\ssrc\s*=\s*"(https?:\/\/[^"]+)"/i)
    return m ? m[1] : null
  }

  /**
   * Payload kind — the surfaces use it for the typed wrong-kind refusals
   * (a pairing QR pasted into the 2FA box must be told where to go, and
   * vice versa; a foreign payload must never silently attach). BOTH pairing
   * carriers are recognized: the words-only `ucrypt-sync://` form AND the
   * versioned full payload `ucrypt-pairing-v1://` (the R96 §3 law — future
   * versions mint v2+; the regex accepts any vN so the scan path stays
   * forward-compatible, while the PARSER itself stays strictly versioned).
   */
  function classify(text) {
    const t = String(text || '').trim()
    if (/^otpauth:\/\//i.test(t)) return 'otpauth'
    if (/^ucrypt-sync:\/\//i.test(t)) return 'pairing'
    if (/^ucrypt-pairing-v\d+:\/\//i.test(t)) return 'pairing'
    return 'other'
  }

  globalThis.UCryptQrScan = {
    decodeFromBlob, decodeFromImage, decodeImageData, classify, pickDropUrl,
    imageMagicFromBytes,
    MAX_IMAGE_BYTES, MAX_DIMENSION, LADDER_MAX_ATTEMPTS,
  }
})()
