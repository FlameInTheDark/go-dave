import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

function requireEnv(name) {
  const value = process.env[name]
  if (!value) {
    throw new Error(`missing required environment variable: ${name}`)
  }
  return value
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function equalBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) {
    return false
  }
  if (left.length !== right.length) {
    return false
  }
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) {
      return false
    }
  }
  return true
}

function encodeMLSVarint(value) {
  if (value < 1 << 6) {
    return Uint8Array.of(value)
  }
  if (value < 1 << 14) {
    return Uint8Array.of(0x40 | (value >> 8), value & 0xff)
  }
  return Uint8Array.of(
    0x80 | (value >> 24),
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  )
}

function encodeOpaqueVector(bytes) {
  return concatBytes(encodeMLSVarint(bytes.length), bytes)
}

function buildServerPacket(sequence, opcode, payload) {
  return concatBytes(
    Uint8Array.of((sequence >> 8) & 0xff, sequence & 0xff, opcode),
    payload,
  )
}

function buildTransitionOpaquePayload(transitionId, value) {
  return concatBytes(
    Uint8Array.of((transitionId >> 8) & 0xff, transitionId & 0xff),
    encodeOpaqueVector(value),
  )
}

function createFetchWithFileSupport() {
  const nativeFetch = globalThis.fetch?.bind(globalThis)

  return async (input, init) => {
    const candidate = input instanceof URL
      ? input
      : input instanceof Request
        ? new URL(input.url)
        : new URL(String(input), import.meta.url)

    if (candidate.protocol === 'file:') {
      const body = await readFile(candidate)
      return new Response(body, {
        headers: { 'Content-Type': 'application/wasm' },
      })
    }

    if (!nativeFetch) {
      throw new Error(`no fetch implementation available for ${candidate.toString()}`)
    }

    return nativeFetch(input, init)
  }
}

async function main() {
  const wasmExecPath = requireEnv('GO_WASM_EXEC')
  const loaderPath = requireEnv('GO_DAVE_LOADER')
  const wasmPath = requireEnv('GO_DAVE_WASM')
  const fetchWithFileSupport = createFetchWithFileSupport()

  const { loadGoDave } = await import(pathToFileURL(loaderPath).href)
  const GoDave = await loadGoDave({
    fetch: fetchWithFileSupport,
    wasmExecUrl: pathToFileURL(wasmExecPath),
    url: pathToFileURL(wasmPath),
  })
  const GoDaveAgain = await loadGoDave({
    fetch: fetchWithFileSupport,
    wasmExecUrl: pathToFileURL(wasmExecPath),
    url: pathToFileURL(wasmPath),
  })
  assert.equal(GoDaveAgain, GoDave)

  const aliceId = '158049329150427136'
  const bobId = '158533742254751744'
  const channelId = '927310423890473011'
  const externalSenderUserId = '999999999'

  const externalSenderKeyPair = GoDave.generateP256Keypair()
  assert.equal(externalSenderKeyPair.private.length, 32)
  assert.equal(externalSenderKeyPair.public[0], 0x04)

  const externalSender = GoDave.encodeExternalSenderPackage(
    externalSenderKeyPair.public,
    externalSenderUserId,
  )
  assert(externalSender.length > 0)

  const alice = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, aliceId, channelId)
  const bob = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, bobId, channelId)

  const externalPacket = buildServerPacket(
    10,
    GoDave.GatewayBinaryOpcode.EXTERNAL_SENDER,
    externalSender,
  )

  const parsedExternalPacket = GoDave.parseGatewayBinaryPacket(externalPacket)
  assert.equal(parsedExternalPacket.sequence, 10)
  assert.equal(parsedExternalPacket.opcode, GoDave.GatewayBinaryOpcode.EXTERNAL_SENDER)
  assert(equalBytes(parsedExternalPacket.payload, externalSender))

  const aliceExternal = alice.handleGatewayBinaryPacket(externalPacket)
  const bobExternal = bob.handleGatewayBinaryPacket(externalPacket)
  assert(aliceExternal.keyPackage instanceof Uint8Array)
  assert(aliceExternal.keyPackagePacket instanceof Uint8Array)
  assert(bobExternal.keyPackage instanceof Uint8Array)
  assert(bobExternal.keyPackagePacket instanceof Uint8Array)
  assert(equalBytes(
    aliceExternal.keyPackagePacket,
    GoDave.encodeKeyPackagePacket(aliceExternal.keyPackage),
  ))

  const aliceStateAfterExternal = alice.getState()
  const bobStateAfterExternal = bob.getState()
  assert.equal(aliceStateAfterExternal.status, GoDave.SessionStatus.PENDING)
  assert.equal(bobStateAfterExternal.status, GoDave.SessionStatus.PENDING)

  const addProposal = alice.createAddProposal(bobExternal.keyPackage)
  assert(addProposal instanceof Uint8Array)
  const messageVector = GoDave.encodeMLSMessageVector([addProposal])
  assert(messageVector instanceof Uint8Array)

  const recognizedUserIds = [aliceId, bobId]
  assert.equal(GoDave.shouldBeCommitter(aliceId, recognizedUserIds), true)
  assert.equal(GoDave.shouldBeCommitter(bobId, recognizedUserIds), false)

  const proposalsPayload = concatBytes(
    Uint8Array.of(GoDave.ProposalsOperationType.APPEND),
    messageVector,
  )
  const proposalsPacket = buildServerPacket(
    11,
    GoDave.GatewayBinaryOpcode.PROPOSALS,
    proposalsPayload,
  )
  const proposalsResult = alice.handleGatewayBinaryPacket(proposalsPacket, recognizedUserIds)
  assert(proposalsResult.commit instanceof Uint8Array)
  assert(proposalsResult.welcome instanceof Uint8Array)
  assert(proposalsResult.commitWelcomePacket instanceof Uint8Array)
  assert(equalBytes(
    proposalsResult.commitWelcomePacket,
    GoDave.encodeCommitWelcomePacket(proposalsResult.commit, proposalsResult.welcome),
  ))

  const transitionId = 77
  const commitPacket = buildServerPacket(
    12,
    GoDave.GatewayBinaryOpcode.ANNOUNCE_COMMIT,
    buildTransitionOpaquePayload(transitionId, proposalsResult.commit),
  )
  const welcomePacket = buildServerPacket(
    13,
    GoDave.GatewayBinaryOpcode.WELCOME,
    buildTransitionOpaquePayload(transitionId, proposalsResult.welcome),
  )

  const aliceCommitResult = alice.handleGatewayBinaryPacket(commitPacket, recognizedUserIds)
  const bobWelcomeResult = bob.handleGatewayBinaryPacket(welcomePacket, recognizedUserIds)
  assert.equal(aliceCommitResult.sendTransitionReady, true)
  assert.equal(aliceCommitResult.transitionId, transitionId)
  assert.equal(bobWelcomeResult.sendTransitionReady, true)
  assert.equal(bobWelcomeResult.transitionId, transitionId)

  const aliceState = alice.getState()
  const bobState = bob.getState()
  assert.equal(aliceState.ready, true)
  assert.equal(bobState.ready, true)
  assert.equal(aliceState.status, GoDave.SessionStatus.ACTIVE)
  assert.equal(bobState.status, GoDave.SessionStatus.ACTIVE)
  assert.equal(aliceState.channelId, channelId)
  assert.equal(bobState.channelId, channelId)
  assert.equal(aliceState.userIds.length, 2)
  assert.equal(bobState.userIds.length, 2)
  assert(aliceState.userIds.includes(aliceId))
  assert(aliceState.userIds.includes(bobId))

  const aliceEpochAuthenticator = alice.getEpochAuthenticator()
  const bobEpochAuthenticator = bob.getEpochAuthenticator()
  assert(aliceEpochAuthenticator instanceof Uint8Array)
  assert(equalBytes(aliceEpochAuthenticator, bobEpochAuthenticator))

  const aliceVerificationCode = alice.getVerificationCode(bobId)
  const bobVerificationCode = bob.getVerificationCode(aliceId)
  assert.equal(aliceVerificationCode, bobVerificationCode)

  const aliceFingerprint = alice.getPairwiseFingerprint(0, bobId)
  const bobFingerprint = bob.getPairwiseFingerprint(0, aliceId)
  assert(equalBytes(aliceFingerprint, bobFingerprint))

  const opusFrame = Uint8Array.of(0x48, 0x65, 0x6c, 0x6c, 0x6f)
  const encryptedOpus = alice.encryptOpus(opusFrame)
  assert(!equalBytes(encryptedOpus, opusFrame))
  const decryptedOpus = bob.decrypt(aliceId, GoDave.MediaType.AUDIO, encryptedOpus)
  assert(equalBytes(decryptedOpus, opusFrame))

  const vp8Frame = Uint8Array.of(
    0x00, 0x00, 0x00, 0x9d, 0x01,
    0x2a, 0x00, 0x00, 0x00, 0x00,
    0xde, 0xad, 0xbe, 0xef,
  )
  const encryptedVp8 = bob.encrypt(GoDave.MediaType.VIDEO, GoDave.Codec.VP8, vp8Frame)
  assert(!equalBytes(encryptedVp8, vp8Frame))
  const decryptedVp8 = alice.decrypt(bobId, GoDave.MediaType.VIDEO, encryptedVp8)
  assert(equalBytes(decryptedVp8, vp8Frame))

  const aliceEncStats = alice.getEncryptionStats(GoDave.MediaType.AUDIO)
  const bobDecStats = bob.getDecryptionStats(aliceId, GoDave.MediaType.AUDIO)
  assert(aliceEncStats.successes >= 1)
  assert(bobDecStats.successes >= 1)
  assert.equal(alice.canPassthrough(bobId), true)

  alice.dispose()
  bob.dispose()
}

main()
  .then(() => {
    process.exit(0)
  })
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
