'use strict'

const b4a = require('b4a')

// UDX v1 wire header: 20 raw bytes at the mouth of every UDP datagram before her throat opens for payload
const MAGIC = 0xff
const VERSION = 0x01
const HEADER_SIZE = 20

// Virtual source-port tag for multiplexing dht-rpc over a shared DataChannel while preserving the puncher's bound UDP port
const VPORT_MAGIC = 0xfe

const TYPE = {
  DATA: 0b000001,
  END: 0b000010,
  SACK: 0b000100,
  MESSAGE: 0b001000,
  DESTROY: 0b010000,
  HEARTBEAT: 0b100000
}

function writeU32LE (buf, val, off) {
  const v = val >>> 0
  buf[off] = v & 0xff
  buf[off + 1] = (v >>> 8) & 0xff
  buf[off + 2] = (v >>> 16) & 0xff
  buf[off + 3] = (v >>> 24) & 0xff
}

function readU32LE (buf, off) {
  return (
    (buf[off] |
      (buf[off + 1] << 8) |
      (buf[off + 2] << 16) |
      (buf[off + 3] << 24)) >>>
    0
  )
}

function readU32BE (buf, off) {
  return (
    ((buf[off] << 24) |
      (buf[off + 1] << 16) |
      (buf[off + 2] << 8) |
      buf[off + 3]) >>>
    0
  )
}

// Pack a 20-byte UDX v1 header + optional SACK blocks + payload ready to slide into libudx
function buildPacket ({
  localId,
  type = 0,
  rwnd = 65536,
  seq = 0,
  ack = 0,
  sacks = null,
  payload = null
}) {
  const sackCount = sacks ? sacks.length : 0
  const sackBytes = sackCount * 8
  const bodyLen = payload ? payload.byteLength : 0
  const dataOffset = bodyLen > 0 && sackBytes > 0 ? sackBytes : 0
  const buf = b4a.allocUnsafe(HEADER_SIZE + sackBytes + bodyLen)

  buf[0] = MAGIC
  buf[1] = VERSION
  buf[2] = type & 0xff
  buf[3] = dataOffset & 0xff

  writeU32LE(buf, localId, 4)
  writeU32LE(buf, rwnd, 8)
  writeU32LE(buf, seq, 12)
  writeU32LE(buf, ack, 16)

  let offset = HEADER_SIZE
  if (sackCount > 0) {
    for (let i = 0; i < sackCount; i++) {
      writeU32LE(buf, sacks[i].start, offset)
      writeU32LE(buf, sacks[i].end, offset + 4)
      offset += 8
    }
  }

  if (bodyLen > 0) {
    b4a.copy(payload, buf, offset)
  }

  return buf
}

// Strip a 20-byte UDX v1 packet open and expose its stream fields and payload
function parsePacket (buf) {
  if (!buf || buf.byteLength < HEADER_SIZE) return null
  if (buf[0] !== MAGIC || buf[1] !== VERSION) return null

  const type = buf[2]
  const dataOffset = buf[3]
  const localId = readU32LE(buf, 4)
  const rwnd = readU32LE(buf, 8)
  const seq = readU32LE(buf, 12)
  const ack = readU32LE(buf, 16)

  let offset = HEADER_SIZE
  const sacks = []

  if (type & TYPE.SACK) {
    const tailLen = buf.byteLength - HEADER_SIZE
    const sackBytes = dataOffset > 0 && dataOffset < tailLen ? dataOffset : tailLen
    const count = (sackBytes / 8) | 0
    for (let i = 0; i < count; i++) {
      sacks.push({
        start: readU32LE(buf, offset),
        end: readU32LE(buf, offset + 4)
      })
      offset += 8
    }
  } else if (dataOffset > 0) {
    if (HEADER_SIZE + dataOffset > buf.byteLength) return null
    offset += dataOffset
  }

  const payload = buf.subarray(offset)
  return { type, dataOffset, localId, rwnd, seq, ack, sacks, payload }
}

// Check if a UDP datagram carries the RFC 5389 STUN magic cookie at bytes 4..7
function isStunPacket (buf) {
  return (
    buf.byteLength >= 20 &&
    (buf[0] & 0xc0) === 0x00 &&
    readU32BE(buf, 4) === 0x2112a442
  )
}

// Check if a UDP datagram is a DTLS 1.2 record (ContentType 20..63)
function isDtlsPacket (buf) {
  return buf.byteLength >= 13 && buf[0] >= 20 && buf[0] <= 63
}

// Check if a UDP datagram is a native UDX v1 frame (0xff 0x01)
function isUdxPacket (buf) {
  return buf.byteLength >= HEADER_SIZE && buf[0] === MAGIC && buf[1] === VERSION
}

module.exports = {
  MAGIC,
  VERSION,
  HEADER_SIZE,
  VPORT_MAGIC,
  TYPE,
  buildPacket,
  parsePacket,
  isStunPacket,
  isDtlsPacket,
  isUdxPacket
}
