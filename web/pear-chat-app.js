import HyperDHT from '../node_modules/hyperdht/index.js'
import Hyperswarm from '../node_modules/hyperswarm/index.js'
import Protomux from '../node_modules/protomux/index.js'
import c from 'compact-encoding'
import b4a from 'b4a'
import BrowserUDX from '../lib/browser-udx.js'

window.HyperDHT = HyperDHT
window.Hyperswarm = Hyperswarm
window.Protomux = Protomux
window.BrowserUDX = BrowserUDX
window.b4a = b4a

const params = new URLSearchParams(window.location.search)
const defaultBootstrap = params.get('bootstrap') || '127.0.0.1:49737'
const defaultTopicHex = params.get('topic') || 'pear-room-1'
const defaultNick = params.get('nick') || `Peer-${Math.floor(100 + Math.random() * 900)}`

const state = {
  nick: defaultNick,
  topicHex: defaultTopicHex,
  bootstrapStr: defaultBootstrap,
  udx: null,
  dht: null,
  swarm: null,
  discovery: null,
  manualPc: null,
  publicKeyHex: '',
  peers: new Map(),
  messages: [],
  status: 'idle'
}

window.__pearChat = state

function updateStatsUI () {
  const pubEl = document.getElementById('local-pubkey')
  const statusEl = document.getElementById('swarm-status')
  const peerCountEl = document.getElementById('peer-count')
  const udxStatsEl = document.getElementById('udx-stats')
  const p2pStatsEl = document.getElementById('p2p-stats')

  if (pubEl) pubEl.textContent = state.publicKeyHex ? state.publicKeyHex.slice(0, 16) + '…' : '—'
  if (statusEl) statusEl.textContent = state.status
  if (peerCountEl) peerCountEl.textContent = String(state.peers.size)
  if (udxStatsEl && state.udx) {
    udxStatsEl.textContent = `TX: ${state.udx.udxPacketsTx} | RX: ${state.udx.udxPacketsRx}`
  }
  if (p2pStatsEl && state.udx) {
    p2pStatsEl.textContent = `Links: ${state.udx.directP2PConnections} | TX: ${state.udx.directP2PPacketsTx} | RX: ${state.udx.directP2PPacketsRx}`
  }
}

function appendMessage (msg) {
  state.messages.push(msg)
  const listEl = document.getElementById('messages')
  if (!listEl) return
  const row = document.createElement('div')
  row.className = 'msg-row'
  row.dataset.sender = msg.nick
  row.innerHTML = `<span class="msg-meta">[${msg.nick} · ${msg.peerKey.slice(0, 8)}]</span> <span class="msg-text"></span>`
  row.querySelector('.msg-text').textContent = msg.text
  listEl.appendChild(row)
  listEl.scrollTop = listEl.scrollHeight
  updateStatsUI()
}

function parseBootstrapList (str) {
  if (!str || str === 'serverless' || str === 'none') return []
  return str
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.includes(':'))
    .map((pair) => {
      const [host, portStr] = pair.split(':')
      return { host: host || '127.0.0.1', port: Number(portStr) || 49737 }
    })
}

async function startPearChat (opts = {}) {
  if (opts.bootstrap !== undefined) state.bootstrapStr = opts.bootstrap
  if (opts.topic) state.topicHex = opts.topic
  if (opts.nick) state.nick = opts.nick

  const nickInput = document.getElementById('nick-input')
  const bootInput = document.getElementById('bootstrap-input')
  const topicInput = document.getElementById('topic-input')
  if (nickInput && !opts.nick) state.nick = nickInput.value.trim() || state.nick
  if (bootInput && opts.bootstrap === undefined) state.bootstrapStr = bootInput.value.trim()
  if (topicInput && !opts.topic) state.topicHex = topicInput.value.trim() || state.topicHex

  if (state.swarm) {
    await state.swarm.destroy()
    state.swarm = null
  }
  if (state.dht) {
    await state.dht.destroy()
    state.dht = null
  }
  if (state.udx) {
    await state.udx.destroy()
    state.udx = null
  }

  state.peers.clear()
  state.status = 'bootstrapping-dht'
  updateStatsUI()

  const externalBootstrap = parseBootstrapList(state.bootstrapStr)
  const udx = new BrowserUDX()
  state.udx = udx
  udx.on('direct-p2p-open', () => updateStatsUI())

  const isLocalMesh = externalBootstrap.length === 0

  const dht = new HyperDHT({
    udx,
    bootstrap: externalBootstrap,
    ephemeral: !isLocalMesh,
    firewalled: !isLocalMesh,
    host: isLocalMesh ? udx.localIp : '127.0.0.1'
  })
  state.dht = dht

  await dht.fullyBootstrapped()
  await dht.bind()
  if (isLocalMesh && dht.io.serverSocket) {
    dht._nat.add(udx.localIp, dht.io.serverSocket.address().port)
  }

  state.publicKeyHex = b4a.toString(dht.defaultKeyPair.publicKey, 'hex')
  state.status = 'joining-swarm'
  updateStatsUI()

  const swarm = new Hyperswarm({
    dht,
    keyPair: dht.defaultKeyPair
  })
  state.swarm = swarm

  swarm.on('connection', (conn) => {
    conn.on('error', () => {})
    const remoteKeyHex = b4a.toString(conn.remotePublicKey, 'hex')

    let chatMessage = null
    const mux = Protomux.from(conn)
    const channel = mux.createChannel({
      protocol: 'pear-p2p-chat',
      id: null,
      onopen () {
        state.peers.set(remoteKeyHex, {
          conn,
          mux,
          channel,
          chatMessage,
          nick: remoteKeyHex.slice(0, 8)
        })
        state.status = 'connected-p2p'
        updateStatsUI()
      },
      onclose () {
        state.peers.delete(remoteKeyHex)
        updateStatsUI()
      }
    })

    chatMessage = channel.addMessage({
      encoding: c.string,
      onmessage (rawJson) {
        try {
          const payload = JSON.parse(rawJson)
          const peerEntry = state.peers.get(remoteKeyHex)
          if (peerEntry && payload.nick) peerEntry.nick = payload.nick
          appendMessage({
            nick: payload.nick || remoteKeyHex.slice(0, 8),
            peerKey: remoteKeyHex,
            text: payload.text,
            ts: payload.ts || Date.now()
          })
        } catch {}
      }
    })

    channel.open()
    state.peers.set(remoteKeyHex, { conn, mux, channel, chatMessage, nick: remoteKeyHex.slice(0, 8) })
    state.status = 'connected-p2p'
    updateStatsUI()

    conn.once('close', () => {
      state.peers.delete(remoteKeyHex)
      updateStatsUI()
    })
  })

  await swarm.listen()
  const topicBuf = HyperDHT.hash(b4a.from(state.topicHex, 'utf8'))
  const discovery = swarm.join(topicBuf, { client: true, server: true })
  state.discovery = discovery
  if (!isLocalMesh) {
    await discovery.flushed()
  }
  if (state.peers.size === 0) state.status = 'swarm-flushed-waiting-peers'
  updateStatsUI()

  return {
    publicKeyHex: state.publicKeyHex,
    topicHex: b4a.toString(topicBuf, 'hex')
  }
}

function waitForIceGathering (pc, timeoutMs = 2500) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve()
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, timeoutMs)
    const check = () => {
      if (pc.iceGatheringState === 'complete') {
        clearTimeout(timer)
        resolve()
      }
    }
    pc.addEventListener('icegatheringstatechange', check)
  })
}

async function createZeroServerInvite () {
  if (!state.udx) {
    await startPearChat({ bootstrap: 'serverless' })
  }
  const pc = new RTCPeerConnection({ iceServers: state.udx.iceServers })
  state.manualPc = pc

  const dc = pc.createDataChannel('udx-invite', {
    ordered: false,
    maxRetransmits: 0
  })

  pc.onconnectionstatechange = () => updateStatsUI()
  dc.onopen = async () => {
    if (!state._remotePeer) return
    const { ip, port, pub } = state._remotePeer
    state.udx.attachPeerChannel(ip, dc)
    state.dht.addNode({ host: ip, port })
    const conn = state.dht.connect(b4a.from(pub, 'hex'), {
      relayAddresses: [{ host: ip, port }]
    })
    conn.once('open', () => {
      state.swarm.emit('connection', conn)
    })
    updateStatsUI()
  }

  const offer = await pc.createOffer()
  await pc.setLocalDescription(offer)
  await waitForIceGathering(pc)

  const myPort = state.dht.io.serverSocket.address().port
  const token = b4a.toString(
    b4a.from(
      JSON.stringify({
        t: 'o',
        ip: state.udx.localIp,
        port: myPort,
        pub: state.publicKeyHex,
        topic: state.topicHex,
        sdp: pc.localDescription
      }),
      'utf8'
    ),
    'base64'
  )

  const outEl = document.getElementById('invite-box')
  if (outEl) outEl.value = token
  state.status = 'invite-created-awaiting-answer'
  updateStatsUI()
  return token
}

async function acceptZeroServerToken (rawToken) {
  if (!rawToken || !rawToken.trim()) return
  const clean = rawToken.trim()
  const decoded = JSON.parse(b4a.toString(b4a.from(clean, 'base64'), 'utf8'))

  if (decoded.t === 'o') {
    if (!state.udx || state.topicHex !== decoded.topic) {
      await startPearChat({ bootstrap: 'serverless', topic: decoded.topic })
    }
    state._remotePeer = {
      ip: decoded.ip,
      port: decoded.port,
      pub: decoded.pub
    }

    const pc = new RTCPeerConnection({ iceServers: state.udx.iceServers })
    state.manualPc = pc

    pc.ondatachannel = (ev) => {
      const dc = ev.channel
      dc.onopen = () => {
        const { ip, port } = state._remotePeer
        state.udx.attachPeerChannel(ip, dc)
        state.dht.addNode({ host: ip, port })
        updateStatsUI()
      }
    }

    await pc.setRemoteDescription(decoded.sdp)
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await waitForIceGathering(pc)

    const myPort = state.dht.io.serverSocket.address().port
    const answerToken = b4a.toString(
      b4a.from(
        JSON.stringify({
          t: 'a',
          ip: state.udx.localIp,
          port: myPort,
          pub: state.publicKeyHex,
          sdp: pc.localDescription
        }),
        'utf8'
      ),
      'base64'
    )

    const outEl = document.getElementById('invite-box')
    if (outEl) outEl.value = answerToken
    state.status = 'answer-ready-copy-back'
    updateStatsUI()
    return answerToken
  }

  if (decoded.t === 'a' && state.manualPc) {
    state._remotePeer = {
      ip: decoded.ip,
      port: decoded.port,
      pub: decoded.pub
    }
    await state.manualPc.setRemoteDescription(decoded.sdp)
    state.status = 'punching-direct-udp'
    updateStatsUI()
    return true
  }
}

function sendChatMessage (text) {
  if (!text || !text.trim()) return 0
  const clean = text.trim()
  const wirePayload = JSON.stringify({
    nick: state.nick,
    text: clean,
    ts: Date.now()
  })

  let sent = 0
  for (const peer of state.peers.values()) {
    if (peer.chatMessage) {
      peer.chatMessage.send(wirePayload)
      sent++
    }
  }

  appendMessage({
    nick: state.nick,
    peerKey: state.publicKeyHex || 'local',
    text: clean,
    ts: Date.now()
  })

  return sent
}

window.startPearChat = startPearChat
window.sendChatMessage = sendChatMessage
window.createZeroServerInvite = createZeroServerInvite
window.acceptZeroServerToken = acceptZeroServerToken

window.addEventListener('DOMContentLoaded', () => {
  const nickInput = document.getElementById('nick-input')
  const bootInput = document.getElementById('bootstrap-input')
  const topicInput = document.getElementById('topic-input')
  const joinBtn = document.getElementById('join-btn')
  const sendBtn = document.getElementById('send-btn')
  const msgInput = document.getElementById('msg-input')
  const createInviteBtn = document.getElementById('create-invite-btn')
  const copyInviteBtn = document.getElementById('copy-invite-btn')
  const acceptInviteBtn = document.getElementById('accept-invite-btn')
  const inviteBox = document.getElementById('invite-box')

  if (nickInput) nickInput.value = state.nick
  if (bootInput) bootInput.value = state.bootstrapStr
  if (topicInput) topicInput.value = state.topicHex

  if (joinBtn) {
    joinBtn.addEventListener('click', () => {
      startPearChat().catch((err) => {
        state.status = `error: ${err.message}`
        updateStatsUI()
      })
    })
  }

  if (createInviteBtn) {
    createInviteBtn.addEventListener('click', () => {
      createZeroServerInvite().catch((err) => {
        state.status = `error: ${err.message}`
        updateStatsUI()
      })
    })
  }

  if (copyInviteBtn && inviteBox) {
    copyInviteBtn.addEventListener('click', () => {
      inviteBox.select()
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(inviteBox.value).catch(() => {})
      } else {
        document.execCommand('copy')
      }
      copyInviteBtn.textContent = 'Copied!'
      setTimeout(() => { copyInviteBtn.textContent = 'Copy Token' }, 1500)
    })
  }

  if (acceptInviteBtn && inviteBox) {
    acceptInviteBtn.addEventListener('click', () => {
      acceptZeroServerToken(inviteBox.value).catch((err) => {
        state.status = `error: ${err.message}`
        updateStatsUI()
      })
    })
  }

  if (sendBtn && msgInput) {
    const doSend = () => {
      const val = msgInput.value
      if (val.trim()) {
        msgInput.value = ''
        sendChatMessage(val)
      }
    }
    sendBtn.addEventListener('click', doSend)
    msgInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doSend()
    })
  }

  setInterval(updateStatsUI, 250)

  if (params.get('autostart') === '1') {
    startPearChat().catch((err) => {
      state.status = `error: ${err.message}`
      updateStatsUI()
    })
  }
})
