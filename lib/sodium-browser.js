'use strict'

const sodium = require('sodium-javascript')
const { unpackneg, pack } = require('sodium-javascript/crypto_sign')
const {
  gf,
  gf0,
  gf1,
  D2,
  A,
  Z,
  M,
  sel25519
} = require('sodium-javascript/internal/ed25519')

function set25519 (r, a) {
  for (let i = 0; i < 16; i++) r[i] = a[i] | 0
}

function cswap (p, q, b) {
  for (let i = 0; i < 4; i++) sel25519(p[i], q[i], b)
}

function add (p, q) {
  const a = gf()
  const b = gf()
  const c = gf()
  const d = gf()
  const e = gf()
  const f = gf()
  const g = gf()
  const h = gf()
  const t = gf()

  Z(a, p[1], p[0])
  Z(t, q[1], q[0])
  M(a, a, t)
  A(b, p[0], p[1])
  A(t, q[0], q[1])
  M(b, b, t)
  M(c, p[3], q[3])
  M(c, c, D2)
  M(d, p[2], q[2])
  A(d, d, d)
  Z(e, b, a)
  Z(f, d, c)
  A(g, d, c)
  A(h, b, a)

  M(p[0], e, f)
  M(p[1], h, g)
  M(p[2], g, f)
  M(p[3], e, h)
}

// Ed25519 scalar multiplication without clamping so noise-curve-ed works in the browser
function crypto_scalarmult_ed25519_noclamp (out, scalar, pk) {
  const q = [gf(), gf(), gf(), gf()]
  const p = [gf(), gf(), gf(), gf()]

  if (!unpackneg(q, pk)) throw new Error('Invalid Ed25519 point')
  Z(q[0], gf0, q[0])
  Z(q[3], gf0, q[3])

  const h = [gf(q[0]), gf(q[1]), gf(q[2]), gf(q[3])]
  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)

  for (let i = 255; i >= 0; --i) {
    const b = (scalar[(i / 8) | 0] >> (i & 7)) & 1
    cswap(p, h, b)
    add(h, p)
    add(p, p)
    cswap(p, h, b)
  }

  pack(out, p)
}

module.exports = Object.assign({}, sodium, {
  crypto_scalarmult_ed25519_BYTES: 32,
  crypto_scalarmult_ed25519_SCALARBYTES: 32,
  crypto_scalarmult_ed25519_noclamp
})
