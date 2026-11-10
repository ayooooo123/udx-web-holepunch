# udx-web-holepunch

Zero-external-WebRTC-dependency `udx` replacement (`WebBridgeUDX` for native Node/Bare + `BrowserUDX` for browsers) that enables browser applications (`window.RTCPeerConnection`) to run unmodified `HyperDHT` and `Hyperswarm` (`dht-rpc` + `Holepuncher` + `@hyperswarm/secret-stream`) and exchange 20-byte `0xff 0x01` UDX v1 frames with native Holepunch peers (`udx-native` C `libudx`) and other browser peers with **zero central signaling server**.

## Architecture

- **`lib/stun.js`** — RFC 5389 / RFC 8445 STUN Binding Request & Response engine (`XOR-MAPPED-ADDRESS`, `MESSAGE-INTEGRITY` HMAC-SHA1, `FINGERPRINT` CRC32) using only Node core `crypto` and `zlib`. Every `UDXSocket` acts simultaneously as a standard STUN server (`srflx` discovery) and an `ice-lite` WebRTC peer on the same UDP port.
- **`lib/dtls.js`** — RFC 6347 DTLS 1.2 Server & Client (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` `0xc02b`, stateless `HelloVerifyRequest` cookie exchange, P-256 ECDHE, `P_SHA256` PRF, `extended_master_secret`, `use_srtp`) using only Node core `crypto`.
- **`lib/sctp.js`** — RFC 4960 / RFC 8831 SCTP over DTLS engine (Castagnoli CRC-32C, `INIT`/`INIT_ACK`/`COOKIE_ECHO`/`COOKIE_ACK`/`DATA`/`SACK`/`HEARTBEAT`/`FORWARD_TSN`/DCEP) for unordered, unreliable WebRTC DataChannels (`ordered: false, maxRetransmits: 0`).
- **`lib/wire.js`** — 20-byte `libudx` v1 header (`0xff 0x01`) encoder/decoder and single-port protocol demux predicates.
- **`lib/cert.js`** — Pre-computed ECDSA P-256 certificate + SHA-256 fingerprint and local `ice-lite` SDP Answer synthesizer (`buildIceLiteSdp`) for zero-signaling cold bootstrap.
- **`lib/native-udx.js`** — `WebBridgeUDX` subclasses `udx-native` to demux STUN, DTLS, `dht-rpc` (`0x03`/`0x13`), 1-byte holepunch probes (`0x00`), peer-to-peer WebRTC signaling envelopes (`0xfd`), and C `libudx` (`0xff 0x01`) on the same UDP socket.
- **`lib/browser-udx.js`** — Pure-JS `UDX`, `UDXSocket`, and `UDXStream` running over `window.RTCPeerConnection` in browsers (or `NodeUdpWebRtcLink` in Node tests) with virtual source-port tagging (`0xfe`) and direct Browser-to-Browser WebRTC P2P upgrade (`0xfd`).
- **`lib/sodium-browser.js`** — Pure-JS twisted-Edwards `crypto_scalarmult_ed25519_noclamp` on top of `sodium-javascript` so `noise-curve-ed` (`HyperDHT` Noise XX handshakes) runs in the browser without native bindings.

## Usage

```js
// Native Holepunch / DHT node (1-line change: pass udx: new WebBridgeUDX())
const HyperDHT = require('hyperdht')
const { WebBridgeUDX } = require('udx-web-holepunch')

const dht = new HyperDHT({ udx: new WebBridgeUDX() })
```

```js
// Browser webpage (zero signaling server)
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const { BrowserUDX } = require('udx-web-holepunch')

const dht = new HyperDHT({ udx: new BrowserUDX(), bootstrap })
const swarm = new Hyperswarm({ dht })
```

## Running Tests & Demos

```bash
npm test
npm run demo
```
