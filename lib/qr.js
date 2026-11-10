'use strict'

const b4a = require('b4a')

// Compress a full WebRTC SDP + HyperDHT identity into a ~155-char binary base64url token for crisp QR codes
function packCompactToken ({ type, ip, port, pubHex, topic, desc }) {
  const sdp = desc.sdp || ''
  const ufrag = ((sdp.match(/a=ice-ufrag:([^\r\n]+)/) || [])[1] || '').trim()
  const pwd = ((sdp.match(/a=ice-pwd:([^\r\n]+)/) || [])[1] || '').trim()
  const fpHex = ((sdp.match(/a=fingerprint:sha-256 ([^\r\n]+)/i) || [])[1] || '').trim()

  const pubBytes = b4a.from(pubHex, 'hex')
  const fpBytes = b4a.from(fpHex.replace(/:/g, ''), 'hex')
  const ufragBytes = b4a.from(ufrag, 'utf8')
  const pwdBytes = b4a.from(pwd, 'utf8')
  const topicBytes = b4a.from(topic || '', 'utf8')

  const cands = []
  const seen = new Set()
  for (const m of sdp.matchAll(/a=candidate:\S+ 1 udp \d+ ([^\s]+) (\d+) typ (host|srflx)/gi)) {
    const host = m[1]
    const cPort = Number(m[2])
    const isSrflx = m[3].toLowerCase() === 'srflx' ? 1 : 0
    if (host.includes(':')) continue
    const key = `${host}:${cPort}`
    if (seen.has(key)) continue
    seen.add(key)
    cands.push({ host, port: cPort, isSrflx })
  }

  cands.sort((a, b) => b.isSrflx - a.isSrflx)
  const selected = cands.slice(0, 4)

  const candChunks = []
  for (const c of selected) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(c.host)) {
      const parts = c.host.split('.').map(Number)
      const buf = b4a.allocUnsafe(7)
      buf[0] = c.isSrflx ? 1 : 0
      buf[1] = parts[0] & 0xff
      buf[2] = parts[1] & 0xff
      buf[3] = parts[2] & 0xff
      buf[4] = parts[3] & 0xff
      buf[5] = (c.port >>> 8) & 0xff
      buf[6] = c.port & 0xff
      candChunks.push(buf)
    } else {
      const hBytes = b4a.from(c.host, 'utf8')
      const buf = b4a.allocUnsafe(4 + hBytes.byteLength)
      buf[0] = 2
      buf[1] = hBytes.byteLength & 0xff
      b4a.copy(hBytes, buf, 2)
      buf[2 + hBytes.byteLength] = (c.port >>> 8) & 0xff
      buf[3 + hBytes.byteLength] = c.port & 0xff
      candChunks.push(buf)
    }
  }

  const ipParts = (ip || '11.1.1.1').split('.').map(Number)
  const headerLen =
    1 + 4 + 2 + 32 + 32 + 1 + ufragBytes.byteLength + 1 + pwdBytes.byteLength + 1 + topicBytes.byteLength + 1
  const candTotal = candChunks.reduce((acc, b) => acc + b.byteLength, 0)
  const out = b4a.allocUnsafe(headerLen + candTotal)

  let off = 0
  out[off++] = type === 'o' ? 1 : 2
  out[off++] = (ipParts[0] || 11) & 0xff
  out[off++] = (ipParts[1] || 1) & 0xff
  out[off++] = (ipParts[2] || 1) & 0xff
  out[off++] = (ipParts[3] || 1) & 0xff
  out[off++] = (port >>> 8) & 0xff
  out[off++] = port & 0xff

  b4a.copy(pubBytes, out, off)
  off += 32
  b4a.copy(fpBytes, out, off)
  off += 32

  out[off++] = ufragBytes.byteLength
  b4a.copy(ufragBytes, out, off)
  off += ufragBytes.byteLength

  out[off++] = pwdBytes.byteLength
  b4a.copy(pwdBytes, out, off)
  off += pwdBytes.byteLength

  out[off++] = topicBytes.byteLength
  b4a.copy(topicBytes, out, off)
  off += topicBytes.byteLength

  out[off++] = selected.length
  for (const ch of candChunks) {
    b4a.copy(ch, out, off)
    off += ch.byteLength
  }

  return toBase64Url(out)
}

function unpackCompactToken (rawToken) {
  let clean = rawToken.trim()
  if (clean.includes('?i=') || clean.includes('&i=')) {
    try {
      const u = new URL(clean)
      clean = u.searchParams.get('i') || clean
    } catch {}
  }

  const buf = fromBase64Url(clean)
  let off = 0
  const typeCode = buf[off++]
  const t = typeCode === 1 ? 'o' : 'a'
  const ip = `${buf[off++]}.${buf[off++]}.${buf[off++]}.${buf[off++]}`
  const port = (buf[off++] << 8) | buf[off++]

  const pub = b4a.toString(buf.subarray(off, off + 32), 'hex')
  off += 32

  const fpBytes = buf.subarray(off, off + 32)
  off += 32
  const fpParts = []
  for (let i = 0; i < 32; i++) {
    fpParts.push(fpBytes[i].toString(16).padStart(2, '0').toUpperCase())
  }
  const fp = fpParts.join(':')

  const ufragLen = buf[off++]
  const ufrag = b4a.toString(buf.subarray(off, off + ufragLen), 'utf8')
  off += ufragLen

  const pwdLen = buf[off++]
  const pwd = b4a.toString(buf.subarray(off, off + pwdLen), 'utf8')
  off += pwdLen

  const topicLen = buf[off++]
  const topic = b4a.toString(buf.subarray(off, off + topicLen), 'utf8')
  off += topicLen

  const candCount = buf[off++]
  const cands = []
  for (let i = 0; i < candCount && off < buf.byteLength; i++) {
    const kind = buf[off++]
    if (kind === 0 || kind === 1) {
      const cHost = `${buf[off++]}.${buf[off++]}.${buf[off++]}.${buf[off++]}`
      const cPort = (buf[off++] << 8) | buf[off++]
      cands.push({ host: cHost, port: cPort, isSrflx: kind === 1 })
    } else if (kind === 2) {
      const hLen = buf[off++]
      const cHost = b4a.toString(buf.subarray(off, off + hLen), 'utf8')
      off += hLen
      const cPort = (buf[off++] << 8) | buf[off++]
      cands.push({ host: cHost, port: cPort, isSrflx: false })
    }
  }

  const lines = [
    'v=0',
    'o=- 1 2 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
    'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${ufrag}`,
    `a=ice-pwd:${pwd}`,
    `a=fingerprint:sha-256 ${fp}`,
    `a=setup:${t === 'o' ? 'actpass' : 'active'}`,
    'a=mid:0',
    'a=sctp-port:5000',
    'a=max-message-size:262144'
  ]

  cands.forEach((c, idx) => {
    const prio = c.isSrflx ? 1686052607 : 2122260223
    const typ = c.isSrflx ? 'srflx raddr 0.0.0.0 rport 0' : 'host'
    lines.push(`a=candidate:${idx + 1} 1 udp ${prio} ${c.host} ${c.port} typ ${typ}`)
  })
  lines.push('a=end-of-candidates', '')

  return {
    t,
    ip,
    port,
    pub,
    topic,
    sdp: {
      type: t === 'o' ? 'offer' : 'answer',
      sdp: lines.join('\r\n')
    }
  }
}

function toBase64Url (u8) {
  let str = ''
  for (let i = 0; i < u8.byteLength; i++) str += String.fromCharCode(u8[i])
  const b64 = typeof btoa === 'function' ? btoa(str) : Buffer.from(u8).toString('base64')
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromBase64Url (str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/')
  if (typeof atob === 'function') {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
  return new Uint8Array(Buffer.from(b64, 'base64'))
}

// ============================================================================
// Zero-dependency ISO/IEC 18004 QR Code Generator (Byte Mode, EC Level L, V1-V14)
// ============================================================================

const VERSION_TABLE_L = [
  null,
  [1, 19, 7, 1, 19, 0, 0],
  [2, 34, 10, 1, 34, 0, 0],
  [3, 55, 15, 1, 55, 0, 0],
  [4, 80, 20, 1, 80, 0, 0],
  [5, 108, 26, 1, 108, 0, 0],
  [6, 136, 18, 2, 68, 0, 0],
  [7, 156, 20, 2, 78, 0, 0],
  [8, 194, 24, 2, 97, 0, 0],
  [9, 232, 30, 2, 116, 0, 0],
  [10, 274, 18, 2, 68, 2, 69],
  [11, 324, 20, 4, 81, 0, 0],
  [12, 370, 24, 2, 92, 2, 93],
  [13, 428, 26, 4, 107, 0, 0],
  [14, 461, 30, 3, 115, 1, 116]
]

const ALIGNMENT_POS = [
  null,
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66]
]

function gfMul (x, y) {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z
}

function rsDivisor (degree) {
  const result = new Uint8Array(degree)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root)
      if (j + 1 < degree) result[j] ^= result[j + 1]
    }
    root = gfMul(root, 0x02)
  }
  return result
}

function rsEncode (data, ecLen) {
  const div = rsDivisor(ecLen)
  const rem = new Uint8Array(ecLen)
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0]
    rem.copyWithin(0, 1)
    rem[ecLen - 1] = 0
    for (let j = 0; j < ecLen; j++) {
      rem[j] ^= gfMul(div[j], factor)
    }
  }
  return rem
}

function encodeQrMatrix (text) {
  const utf8 = b4a.from(text, 'utf8')
  const len = utf8.byteLength

  let verInfo = null
  for (let v = 1; v < VERSION_TABLE_L.length; v++) {
    const [, totalData] = VERSION_TABLE_L[v]
    const hdrBits = v <= 9 ? 4 + 8 : 4 + 16
    const maxPayload = Math.floor((totalData * 8 - hdrBits) / 8)
    if (len <= maxPayload) {
      verInfo = VERSION_TABLE_L[v]
      break
    }
  }
  if (!verInfo) throw new Error('Text too long for QR V14')

  const [version, totalDataBytes, ecLen, g1Blocks, g1Bytes, g2Blocks, g2Bytes] = verInfo
  const bits = []
  const pushBits = (val, n) => {
    for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1)
  }

  pushBits(0b0100, 4)
  pushBits(len, version <= 9 ? 8 : 16)
  for (let i = 0; i < len; i++) pushBits(utf8[i], 8)

  const maxBits = totalDataBytes * 8
  const term = Math.min(4, maxBits - bits.length)
  pushBits(0, term)
  while (bits.length % 8 !== 0) bits.push(0)

  const dataBytes = new Uint8Array(totalDataBytes)
  for (let i = 0; i < bits.length / 8; i++) {
    let b = 0
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j]
    dataBytes[i] = b
  }
  const pads = [0xec, 0x11]
  for (let i = bits.length / 8, p = 0; i < totalDataBytes; i++, p ^= 1) {
    dataBytes[i] = pads[p]
  }

  const dataBlocks = []
  const ecBlocks = []
  let offset = 0
  for (let i = 0; i < g1Blocks; i++) {
    const blk = dataBytes.subarray(offset, offset + g1Bytes)
    offset += g1Bytes
    dataBlocks.push(blk)
    ecBlocks.push(rsEncode(blk, ecLen))
  }
  for (let i = 0; i < g2Blocks; i++) {
    const blk = dataBytes.subarray(offset, offset + g2Bytes)
    offset += g2Bytes
    dataBlocks.push(blk)
    ecBlocks.push(rsEncode(blk, ecLen))
  }

  const interleaved = []
  const maxDataLen = Math.max(g1Bytes, g2Bytes)
  for (let i = 0; i < maxDataLen; i++) {
    for (const blk of dataBlocks) {
      if (i < blk.length) interleaved.push(blk[i])
    }
  }
  for (let i = 0; i < ecLen; i++) {
    for (const blk of ecBlocks) {
      interleaved.push(blk[i])
    }
  }

  const size = 17 + version * 4
  const modules = Array.from({ length: size }, () => new Uint8Array(size))
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size))

  const setFunc = (r, c, val) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      modules[r][c] = val ? 1 : 0
      isFunc[r][c] = 1
    }
  }

  const drawFinder = (r0, c0) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const on =
          dr >= 0 &&
          dr <= 6 &&
          dc >= 0 &&
          dc <= 6 &&
          (dr === 0 ||
            dr === 6 ||
            dc === 0 ||
            dc === 6 ||
            (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4))
        setFunc(r0 + dr, c0 + dc, on)
      }
    }
  }
  drawFinder(0, 0)
  drawFinder(0, size - 7)
  drawFinder(size - 7, 0)

  for (let i = 8; i < size - 8; i++) {
    setFunc(6, i, i % 2 === 0)
    setFunc(i, 6, i % 2 === 0)
  }

  const align = ALIGNMENT_POS[version]
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if (
        (i === 0 && j === 0) ||
        (i === 0 && j === align.length - 1) ||
        (i === align.length - 1 && j === 0)
      ) {
        continue
      }
      const cr = align[i]
      const cc = align[j]
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          setFunc(cr + dr, cc + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1)
        }
      }
    }
  }

  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      setFunc(8, i, false)
      setFunc(i, 8, false)
    }
    if (i < 8) {
      setFunc(8, size - 1 - i, false)
      setFunc(size - 1 - i, 8, false)
    }
  }
  setFunc(size - 8, 8, true)

  if (version >= 7) {
    let rem = version
    for (let i = 0; i < 12; i++) {
      rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    }
    const vBits = (version << 12) | rem
    for (let i = 0; i < 18; i++) {
      const bit = ((vBits >>> i) & 1) !== 0
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      setFunc(a, b, bit)
      setFunc(b, a, bit)
    }
  }

  let bitIdx = 0
  let upward = true
  const totalBits = interleaved.length * 8
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j
        const r = upward ? size - 1 - vert : vert
        if (!isFunc[r][c]) {
          let bit = 0
          if (bitIdx < totalBits) {
            bit = (interleaved[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1
            bitIdx++
          }
          if ((r + c) % 2 === 0) bit ^= 1
          modules[r][c] = bit
        }
      }
    }
    upward = !upward
  }

  let fRem = 0b01000
  for (let i = 0; i < 10; i++) {
    fRem = (fRem << 1) ^ ((fRem >>> 9) * 0x537)
  }
  const fBits = ((0b01000 << 10) | fRem) ^ 0x5412
  const getFBit = (i) => ((fBits >>> i) & 1) !== 0

  for (let i = 0; i <= 5; i++) setFunc(i, 8, getFBit(i))
  setFunc(7, 8, getFBit(6))
  setFunc(8, 8, getFBit(7))
  setFunc(8, 7, getFBit(8))
  for (let i = 9; i < 15; i++) setFunc(8, 14 - i, getFBit(i))

  for (let i = 0; i < 8; i++) setFunc(8, size - 1 - i, getFBit(i))
  for (let i = 8; i < 15; i++) setFunc(size - 15 + i, 8, getFBit(i))
  setFunc(size - 8, 8, true)

  return { size, modules }
}

function renderQrSvg (text, quietZone = 3) {
  const { size, modules } = encodeQrMatrix(text)
  const total = size + quietZone * 2
  let path = ''
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r][c]) {
        path += `M${c + quietZone},${r + quietZone}h1v1h-1z`
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges"><rect width="${total}" height="${total}" fill="#ffffff"/><path d="${path}" fill="#000000"/></svg>`
}

module.exports = {
  packCompactToken,
  unpackCompactToken,
  encodeQrMatrix,
  renderQrSvg
}
