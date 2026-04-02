export interface SigningKeyPair {
  private: Uint8Array
  public: Uint8Array
}

export interface SessionState {
  protocolVersion: number
  userId: string
  channelId: string
  epoch: number | null
  ownLeafIndex: number | null
  ciphersuite: number
  status: number
  ready: boolean
  voicePrivacyCode: string
  userIds: string[]
}

export interface CommitWelcome {
  commit: Uint8Array | null
  welcome: Uint8Array | null
}

export interface GatewayBinaryPacket {
  sequence: number
  opcode: number
  payload: Uint8Array
}

export interface GatewayBinaryResult {
  sequence: number
  opcode: number
  keyPackage: Uint8Array | null
  keyPackagePacket: Uint8Array | null
  commit: Uint8Array | null
  welcome: Uint8Array | null
  commitWelcomePacket: Uint8Array | null
  transitionId: number | null
  sendTransitionReady: boolean
}

export interface EncryptionStats {
  successes: number
  failures: number
  duration: number
  attempts: number
  maxAttempts: number
}

export interface DecryptionStats {
  successes: number
  failures: number
  duration: number
  attempts: number
  passthroughs: number
}

export interface GoDaveSession {
  id: number
  dispose(): void
  getState(): SessionState
  getEpochAuthenticator(): Uint8Array | null
  reinit(protocolVersion: number, userId: string, channelId: string, keyPair?: SigningKeyPair | null): void
  reset(): void
  setExternalSender(data: Uint8Array | ArrayBuffer): void
  getSerializedKeyPackage(): Uint8Array
  getKeyPackagePacket(): Uint8Array
  createAddProposal(keyPackage: Uint8Array | ArrayBuffer): Uint8Array
  processProposals(operationType: number, payload: Uint8Array | ArrayBuffer, recognizedUserIds?: string[] | null): CommitWelcome
  processWelcome(welcome: Uint8Array | ArrayBuffer): void
  processCommit(commit: Uint8Array | ArrayBuffer): void
  handleGatewayBinaryPacket(packet: Uint8Array | ArrayBuffer, recognizedUserIds?: string[] | null): GatewayBinaryResult
  handleGatewayBinaryMessage(sequence: number, opcode: number, payload: Uint8Array | ArrayBuffer, recognizedUserIds?: string[] | null): GatewayBinaryResult
  getVerificationCode(userId: string): string
  getPairwiseFingerprint(version: number, userId: string): Uint8Array
  encrypt(mediaType: number, codec: number, packet: Uint8Array | ArrayBuffer): Uint8Array | null
  encryptOpus(packet: Uint8Array | ArrayBuffer): Uint8Array | null
  getEncryptionStats(mediaType?: number | null): EncryptionStats
  decrypt(userId: string, mediaType: number, packet: Uint8Array | ArrayBuffer): Uint8Array | null
  getDecryptionStats(userId: string, mediaType?: number | null): DecryptionStats
  getUserIds(): string[]
  canPassthrough(userId: string): boolean
  setPassthroughMode(enabled: boolean, transitionExpiry?: number | null): void
}

export interface GoDaveModule {
  DAVE_PROTOCOL_VERSION: number
  Codec: Record<string, number>
  MediaType: Record<string, number>
  ProposalsOperationType: Record<string, number>
  SessionStatus: Record<string, number>
  GatewayBinaryOpcode: Record<string, number>
  createSession(protocolVersion: number, userId: string, channelId: string, keyPair?: SigningKeyPair | null): GoDaveSession
  generateP256Keypair(): SigningKeyPair
  generateDisplayableCode(data: Uint8Array | ArrayBuffer, desiredLength: number, groupSize: number): string
  generateKeyFingerprint(version: number, key: Uint8Array | ArrayBuffer, userId: string): Uint8Array
  generatePairwiseFingerprint(
    version: number,
    localKey: Uint8Array | ArrayBuffer,
    localUserId: string,
    remoteKey: Uint8Array | ArrayBuffer,
    remoteUserId: string,
  ): Uint8Array
  shouldBeCommitter(selfUserId: string, recognizedUserIds?: string[] | null): boolean
  parseGatewayBinaryPacket(packet: Uint8Array | ArrayBuffer): GatewayBinaryPacket
  encodeKeyPackagePacket(keyPackage: Uint8Array | ArrayBuffer): Uint8Array
  encodeExternalSenderPackage(signatureKey: Uint8Array | ArrayBuffer, userId: string): Uint8Array
  encodeMLSMessageVector(messages: Array<Uint8Array | ArrayBuffer>): Uint8Array
  encodeCommitWelcomePacket(commit: Uint8Array | ArrayBuffer, welcome?: Uint8Array | ArrayBuffer | null): Uint8Array
}

export interface GoRuntime {
  importObject: WebAssembly.Imports
  run(instance: WebAssembly.Instance): Promise<unknown> | unknown
}

export interface LoadGoDaveOptions {
  url?: string | URL
  wasmExecUrl?: string | URL
  go?: GoRuntime
  fetch?: typeof fetch
}

export function loadGoDave(options?: LoadGoDaveOptions): Promise<GoDaveModule>

export default loadGoDave
