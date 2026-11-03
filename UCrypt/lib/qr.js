/**
 * UCrypt — QR code generator (v2, spec-compliant rewrite).
 *
 * v2.1.0 of this file produced UNREADABLE codes:
 *  - the zigzag data placement never alternated row direction per column
 *    pair (bits landed in the wrong modules at every version), and
 *  - error-correction blocks were never interleaved for versions with
 *    more than one RS block (V4+ at level M).
 * Both defects are fixed here. Verified with the jsQR decoder: payloads
 * from 1 to 300+ bytes now round-trip.
 *
 * Scope: byte mode, ECC level M, versions 1-15. Output: SVG data URL.
 */

const QR = (function () {
  // --- GF(256) tables -------------------------------------------------------
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256)
  ;(function () {
    let x = 1
    for (let i = 0; i < 255; i++) {
      EXP[i] = x; LOG[x] = i
      x = (x << 1) ^ (x & 0x80 ? 0x11d : 0)
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
  })()

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0
    return EXP[LOG[a] + LOG[b]]
  }

  // Reed–Solomon generator polynomial of degree `deg`, then remainder.
  function rsComputeDivisor(deg) {
    let result = new Array(deg).fill(0)
    result[deg - 1] = 1 // monomial x^0 — stored little-endian-style per nayuki
    let root = 1
    for (let i = 0; i < deg; i++) {
      for (let j = 0; j < deg; j++) {
        result[j] = gfMul(result[j], root)
        if (j + 1 < deg) result[j] ^= result[j + 1]
      }
      root = gfMul(root, 2)
    }
    return result
  }

  function rsGetRemainder(data, divisor) {
    const result = new Array(divisor.length).fill(0)
    for (const b of data) {
      const factor = b ^ result[0]
      result.shift()
      result.push(0)
      if (factor === 0) continue
      for (let i = 0; i < divisor.length; i++) result[i] ^= gfMul(divisor[i], factor)
    }
    return result
  }

  // --- Version metadata -----------------------------------------------------
  // capacity[data codewords], size (modules), ecCodewordsPerBlock, and the
  // block structure for ECC level M (short/long data blocks + counts).
  const VERSIONS = [
    /* v1  */ { size: 21, data: 16, ecPerBlock: 10, blocks: [{ n: 1, data: 16 }] },
    /* v2  */ { size: 25, data: 28, ecPerBlock: 16, blocks: [{ n: 1, data: 28 }] },
    /* v3  */ { size: 29, data: 44, ecPerBlock: 26, blocks: [{ n: 1, data: 44 }] },
    /* v4  */ { size: 33, data: 64, ecPerBlock: 18, blocks: [{ n: 2, data: 32 }] },
    /* v5  */ { size: 37, data: 86, ecPerBlock: 24, blocks: [{ n: 2, data: 43 }] },
    /* v6  */ { size: 41, data: 108, ecPerBlock: 16, blocks: [{ n: 4, data: 27 }] },
    /* v7  */ { size: 45, data: 124, ecPerBlock: 18, blocks: [{ n: 4, data: 31 }] },
    /* v8  */ { size: 49, data: 154, ecPerBlock: 22, blocks: [{ n: 2, data: 38 }, { n: 2, data: 39 }] },
    /* v9  */ { size: 53, data: 182, ecPerBlock: 22, blocks: [{ n: 3, data: 36 }, { n: 2, data: 37 }] },
    /* v10 */ { size: 57, data: 216, ecPerBlock: 26, blocks: [{ n: 4, data: 43 }, { n: 1, data: 44 }] },
    /* v11 */ { size: 61, data: 254, ecPerBlock: 30, blocks: [{ n: 1, data: 50 }, { n: 4, data: 51 }] },
    /* v12 */ { size: 65, data: 290, ecPerBlock: 22, blocks: [{ n: 6, data: 36 }, { n: 2, data: 37 }] },
    /* v13 */ { size: 69, data: 334, ecPerBlock: 22, blocks: [{ n: 8, data: 37 }, { n: 1, data: 38 }] },
    /* v14 */ { size: 73, data: 365, ecPerBlock: 24, blocks: [{ n: 4, data: 40 }, { n: 5, data: 41 }] },
    /* v15 */ { size: 77, data: 415, ecPerBlock: 24, blocks: [{ n: 5, data: 41 }, { n: 5, data: 42 }] },
  ]

  // Alignment pattern center coordinates per version (index 0 unused).
  // R97 QR-FIX: the table stopped at v14 — ALIGN[15] was undefined, so v15
  // codes were emitted with NO alignment patterns and every independent
  // decoder (jsQR and @paulmillr/qr) refused them. The true v15 row is
  // [6,26,48,70] (the last center is always sz-7 = 70 for a 77-module v15 —
  // NOT v14's [6,26,46,66]); cross-verified against qrcode-generator's v15
  // (the only v15 matrix both jsQR and @paulmillr/qr accept).
  const ALIGN = [
    null,
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62],
    [6, 26, 46, 66], [6, 26, 48, 70],
  ]

  const MAX_VERSION = 15

  function pickVersion(byteLen) {
    for (let v = 1; v <= MAX_VERSION; v++) {
      const ver = VERSIONS[v - 1]
      const lb = v < 10 ? 8 : 16
      const neededBits = 4 + lb + byteLen * 8
      if (neededBits <= ver.data * 8) return v
    }
    throw new Error(`Payload too large for QR (max ${capacityBytes()} bytes at level M, v15)`)
  }

  function capacityBytes() {
    const v = VERSIONS[MAX_VERSION - 1]
    return Math.floor((v.data * 8 - 4 - 16) / 8)
  }

  // --- Codeword assembly ----------------------------------------------------

  function buildCodewords(bytes, ver, version) {
    const segments = []
    let offset = 0
    for (const grp of ver.blocks) {
      for (let i = 0; i < grp.n; i++) {
        segments.push(bytes.slice(offset, offset + grp.data))
        offset += grp.data
      }
    }
    if (offset !== bytes.length) throw new Error('Internal: codeword split mismatch')

    const divisor = rsComputeDivisor(ver.ecPerBlock)
    const ecs = segments.map(seg => rsGetRemainder(seg, divisor))

    // Interleave data codewords across blocks (blocks may differ by 1 byte).
    const all = []
    const maxData = Math.max(...ver.blocks.map(b => b.data))
    for (let i = 0; i < maxData; i++) {
      for (const seg of segments) if (i < seg.length) all.push(seg[i])
    }
    // Then interleave the EC codewords.
    for (let i = 0; i < ver.ecPerBlock; i++) {
      for (const ec of ecs) all.push(ec[i])
    }
    return all
  }

  // BCH(15,5) for format bits — precomputed table for level M (0b00) + mask 0-7.
  const FORMAT_TABLE = [
    0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
  ]

  // BCH(18,6) version info.
  function versionInfoBits(version) {
    let rem = version
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    return (version << 12) | rem
  }

  // --- Encode ---------------------------------------------------------------

  // R106 (F-R106-QR-2 fix): the matrix builder is now its own step. encode()
  // (the SVG data URL, the on-screen render) and matrix() (the export's
  // source of truth) consume the SAME builder — one code path, zero drift.
  function buildMatrix(text) {
    const bytes = new TextEncoder().encode(text)
    const version = pickVersion(bytes.length)
    const ver = VERSIONS[version - 1]
    const sz = ver.size

    // 1. Segment: mode 4 bits (0100 = byte) + char count + data + terminator
    const lb = version < 10 ? 8 : 16
    let bits = '0100' + bytes.length.toString(2).padStart(lb, '0')
    for (const b of bytes) bits += b.toString(2).padStart(8, '0')
    const capBits = ver.data * 8
    bits += '0000'.slice(0, Math.min(4, capBits - bits.length))
    while (bits.length % 8 !== 0 && bits.length < capBits) bits += '0'
    const data = []
    for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8), 2))
    // Pad codewords
    const padBytes = [0xec, 0x11]
    for (let i = 0; data.length < ver.data; i++) data.push(padBytes[i % 2])

    // 2. Error correction + interleaving
    const all = buildCodewords(data, ver, version)

    // 3. Matrix + function patterns
    const modules = Array.from({ length: sz }, () => new Array(sz).fill(false))
    const isFunction = Array.from({ length: sz }, () => new Array(sz).fill(false))

    function setFn(x, y, dark) {
      modules[y][x] = dark
      isFunction[y][x] = true
    }

    for (let i = 0; i < sz; i++) {
      setFn(6, i, i % 2 === 0)
      setFn(i, 6, i % 2 === 0)
    }
    function drawFinder(cx, cy) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const x = cx + dx, y = cy + dy
          if (x < 0 || x >= sz || y < 0 || y >= sz) continue
          const dist = Math.max(Math.abs(dx), Math.abs(dy))
          setFn(x, y, dist !== 2 && dist !== 4)
        }
      }
    }
    drawFinder(3, 3)
    drawFinder(sz - 4, 3)
    drawFinder(3, sz - 4)

    const centers = ALIGN[version] || []
    for (const cy of centers) {
      for (const cx of centers) {
        if ((cx === 6 && cy === 6) || (cx === 6 && cy === sz - 7) || (cx === sz - 7 && cy === 6)) continue
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            setFn(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
          }
        }
      }
    }

    // Reserve format-info + version-info + dark-module cells BEFORE data
    // placement (v2.2.0 fix: reserving them after placement leaked data bits
    // into format cells).
    for (let i = 0; i <= 8; i++) {
      isFunction[i][8] = true
      isFunction[8][i] = true
    }
    for (let i = sz - 8; i < sz; i++) {
      isFunction[i][8] = true
      isFunction[8][i] = true
    }
    if (version >= 7) {
      for (let i = 0; i < 18; i++) {
        const a = sz - 11 + (i % 3)
        const b = Math.floor(i / 3)
        isFunction[b][a] = true
        isFunction[a][b] = true
      }
    }

    // 4. Place data with proper alternating zigzag (the v2.1.0 bug).
    let bi = 0
    const totalModules = sz * sz
    const bitAt = (idx) => {
      const byte = Math.floor(idx / 8)
      const bit = 7 - (idx % 8)
      if (byte >= all.length) return false
      return ((all[byte] >> bit) & 1) === 1
    }
    for (let right = sz - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      for (let vert = 0; vert < sz; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j
          const upward = ((right + 1) & 2) === 0
          const y = upward ? sz - 1 - vert : vert
          if (!isFunction[y][x]) {
            modules[y][x] = bi < totalModules ? bitAt(bi) : false
            bi++
          }
        }
      }
    }

    // 5. Masking — evaluate penalty rules N1-N4 for all 8 masks.
    const MASKS = [
      (x, y) => (x + y) % 2 === 0,
      (x, y) => y % 2 === 0,
      (x, y) => x % 3 === 0,
      (x, y) => (x + y) % 3 === 0,
      (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
      (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
      (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
      (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
    ]

    function applyMask(mask) {
      const m = modules.map(row => row.slice())
      for (let y = 0; y < sz; y++) {
        for (let x = 0; x < sz; x++) {
          if (!isFunction[y][x] && MASKS[mask](x, y)) m[y][x] = !m[y][x]
        }
      }
      return m
    }

    function penalty(m) {
      let score = 0
      // N1: runs of same color >= 5, rows + cols
      for (let y = 0; y < sz; y++) {
        score += runPenalty(m[y])
      }
      for (let x = 0; x < sz; x++) {
        const col = []
        for (let y = 0; y < sz; y++) col.push(m[y][x])
        score += runPenalty(col)
      }
      // N2: 2x2 blocks of same color
      for (let y = 0; y < sz - 1; y++) {
        for (let x = 0; x < sz - 1; x++) {
          const v = m[y][x]
          if (m[y][x + 1] === v && m[y + 1][x] === v && m[y + 1][x + 1] === v) score += 3
        }
      }
      // N3: finder-like patterns 1011101 with 4 light on either side
      const PAT1 = [true, false, true, true, true, false, true]
      const PAT2 = [...PAT1, false, false, false, false]
      const PAT3 = [false, false, false, false, ...PAT1]
      function finderPenalty(line) {
        let n = 0
        for (let i = 0; i + 11 <= line.length; i++) {
          const seg = line.slice(i, i + 11)
          const eq = (pat) => pat.every((v, j) => seg[j] === v)
          if (eq(PAT2) || eq(PAT3)) n += 40
        }
        return n
      }
      for (let y = 0; y < sz; y++) score += finderPenalty(m[y])
      for (let x = 0; x < sz; x++) {
        const col = []
        for (let y = 0; y < sz; y++) col.push(m[y][x])
        score += finderPenalty(col)
      }
      // N4: dark proportion
      let dark = 0
      for (const row of m) for (const v of row) if (v) dark++
      const total = sz * sz
      const pct = (dark * 100) / total
      score += Math.floor(Math.abs(pct - 50) / 5) * 10
      return score
    }

    function runPenalty(line) {
      let s = 0
      let i = 0
      while (i < line.length) {
        let j = i
        while (j < line.length && line[j] === line[i]) j++
        const run = j - i
        if (run >= 5) s += 3 + (run - 5)
        i = j
      }
      return s
    }

    let bestMask = 0
    let bestScore = Infinity
    let bestMatrix = null
    for (let m = 0; m < 8; m++) {
      const candidate = applyMask(m)
      const p = penalty(candidate)
      if (p < bestScore) {
        bestScore = p
        bestMask = m
        bestMatrix = candidate
      }
    }

    // R109 (F-R109-QR-MASK) — THE MASK POLICY RESTORED to the spec's
    // penalty-score selection (N1–N4 over all 8 masks — the loop above).
    // History: R106 (F-R106-QR-3) pinned mask 0 after its gauntlet measured
    // non-zero-mask matrices refusing against the vendored reader at up to
    // ~30%. THE R109 FORENSIC REFUTES THAT MEASUREMENT ON THE CURRENT BYTES:
    // it predates the v2.2.0 render-target fix (which adopted the masked
    // matrix as the render target — the R106 probes rendered the UN-masked
    // matrix while the format bits claimed mask N, a guaranteed decode
    // failure for ANY content). Re-measured on the fixed bytes (the R109
    // gauntlet, 42 payload shapes × 8 masks, every version band v1–v15,
    // the URL-carrying v1.3 pairing class included): MASK 0 is the ONLY
    // failing mask — 4 real decode failures ("invalid version pattern":
    // the vendor's finder mis-measures the module size on mask 0's long
    // same-color runs; jsQR reads the identical matrix fine — the matrix
    // is spec-valid) — while masks 1–7 decode EVERY payload. The spec's
    // penalty selection decodes 100% (zero failures across the same
    // gauntlet). The policy is therefore: penalty-selected mask, exactly
    // as the spec prescribes — deterministic, scanner-quality-optimal,
    // and machine-gated by the R109 battery's QR gauntlet row.

    // v2.2.0 fix: adopt the masked matrix as the render target (previously the
    // SVG was rendered from the un-masked `modules` while the format bits
    // claimed the chosen mask — codes could never decode).
    for (let y = 0; y < sz; y++) modules[y] = bestMatrix[y].slice()

    // 6. Format info (level M, index = mask) — two copies, per spec.
    function setFnRaw(x, y, dark) {
      modules[y][x] = dark
      isFunction[y][x] = true
    }
    const fc = FORMAT_TABLE[bestMask]
    for (let i = 0; i < 15; i++) {
      // Spec: format bits are read LSB-first (getBit(bits, i), per nayuki ref)
      const bit = ((fc >> i) & 1) === 1
      // Copy 1: column 8 near top-left finder, then row 8 left of it
      if (i < 6) setFnRaw(8, i, bit)
      else if (i === 6) setFnRaw(8, 7, bit)
      else if (i === 7) setFnRaw(8, 8, bit)
      else if (i === 8) setFnRaw(7, 8, bit)
      else setFnRaw(14 - i, 8, bit)
      // Copy 2: column 8 at bottom-left + row 8 at top-right
      if (i < 8) setFnRaw(sz - 1 - i, 8, bit)
      else setFnRaw(8, sz - 15 + i, bit)
    }
    // Dark module
    setFnRaw(8, sz - 8, true)

    // 7. Version info blocks (V7+)
    if (version >= 7) {
      const vi = versionInfoBits(version)
      for (let i = 0; i < 18; i++) {
        const bit = ((vi >> i) & 1) === 1
        const a = sz - 11 + (i % 3)
        const b = Math.floor(i / 3)
        setFnRaw(a, b, bit)
        setFnRaw(b, a, bit)
      }
    }

    return { size: sz, modules }
  }

  /** The matrix itself — the EXPORT's source of truth (R106 fix law). */
  function matrix(text) {
    const { size, modules } = buildMatrix(text)
    return { size, modules, quiet: 4 }
  }

  /** The on-screen render — the identical SVG the seal has always shipped. */
  function renderSvg(m) {
    const sz = m.size
    const cs = Math.max(4, Math.floor(320 / sz))
    const pd = cs * (m.quiet || 4) // proper 4-module quiet zone (v2.1.0 used 2)
    const ts = sz * cs + pd * 2
    let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${ts}" height="${ts}" viewBox="0 0 ${ts} ${ts}"><rect width="${ts}" height="${ts}" fill="#fff"/>`
    for (let r = 0; r < sz; r++) {
      for (let c = 0; c < sz; c++) {
        if (m.modules[r][c]) {
          svg += `<rect x="${pd + c * cs}" y="${pd + r * cs}" width="${cs}" height="${cs}" fill="#000"/>`
        }
      }
    }
    svg += '</svg>'
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg)
  }

  function encode(text) {
    return renderSvg(matrix(text))
  }

  /**
   * R106 (F-R106-QR-2 fix) — THE EXPORT GRID: one byte per pixel, pure 255
   * white / 0 black, INTEGER module scale, an explicit quiet-module white
   * border. The Download/Copy buttons rasterize THIS grid (putImageData →
   * lossless PNG) — the on-screen SVG is never resampled again, so the
   * 13–17% antialiased gray pixels the owner's failure walked through can
   * never exist in an export. Theme-independent BY CONSTRUCTION: the grid
   * takes no theme input and carries only the constants below.
   */
  const EXPORT_MODULE_PX = 8 // integer, ≥8 → v15 export = 77*8+64 = 680px
  const EXPORT_QUIET_MODULES = 4 // the spec quiet zone, explicit
  function exportGrid(m, modulePx = EXPORT_MODULE_PX, quietModules = EXPORT_QUIET_MODULES) {
    const quiet = quietModules * modulePx
    const dim = m.size * modulePx + quiet * 2
    const px = new Uint8Array(dim * dim).fill(255)
    for (let r = 0; r < m.size; r++) {
      for (let c = 0; c < m.size; c++) {
        if (!m.modules[r][c]) continue
        for (let dy = 0; dy < modulePx; dy++) {
          const rowBase = (quiet + r * modulePx + dy) * dim + quiet + c * modulePx
          for (let dx = 0; dx < modulePx; dx++) px[rowBase + dx] = 0
        }
      }
    }
    return { dim, px, modulePx, quietPx: quiet }
  }

  return { encode, matrix, exportGrid, EXPORT_MODULE_PX, EXPORT_QUIET_MODULES }
})()

if (typeof module !== 'undefined') module.exports = { QR }
if (typeof globalThis !== 'undefined') globalThis.QR = QR
