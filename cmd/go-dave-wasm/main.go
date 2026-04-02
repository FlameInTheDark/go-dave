//go:build js && wasm

package main

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall/js"

	dave "github.com/FlameInTheDark/go-dave"
)

var (
	moduleFuncs []js.Func

	sessionMu     sync.Mutex
	nextSessionID int
	sessions      = make(map[int]*jsSession)
)

type jsSession struct {
	id      int
	session *dave.DAVESession
	funcs   []js.Func
}

const jsErrorMarker = "__goDaveError"

func main() {
	module := js.Global().Get("Object").New()
	module.Set("DAVE_PROTOCOL_VERSION", dave.DAVEProtocolVersion)
	module.Set("Codec", mapObject(map[string]any{
		"UNKNOWN": int(dave.CodecUnknown),
		"OPUS":    int(dave.CodecOpus),
		"VP8":     int(dave.CodecVP8),
		"VP9":     int(dave.CodecVP9),
		"H264":    int(dave.CodecH264),
		"H265":    int(dave.CodecH265),
		"AV1":     int(dave.CodecAV1),
	}))
	module.Set("MediaType", mapObject(map[string]any{
		"AUDIO": int(dave.MediaTypeAudio),
		"VIDEO": int(dave.MediaTypeVideo),
	}))
	module.Set("ProposalsOperationType", mapObject(map[string]any{
		"APPEND": int(dave.ProposalsAppend),
		"REVOKE": int(dave.ProposalsRevoke),
	}))
	module.Set("SessionStatus", mapObject(map[string]any{
		"INACTIVE":          int(dave.SessionStatusInactive),
		"PENDING":           int(dave.SessionStatusPending),
		"AWAITING_RESPONSE": int(dave.SessionStatusAwaitingResponse),
		"ACTIVE":            int(dave.SessionStatusActive),
	}))
	module.Set("GatewayBinaryOpcode", mapObject(map[string]any{
		"EXTERNAL_SENDER": int(dave.GatewayBinaryOpcodeExternalSender),
		"KEY_PACKAGE":     int(dave.GatewayBinaryOpcodeKeyPackage),
		"PROPOSALS":       int(dave.GatewayBinaryOpcodeProposals),
		"COMMIT_WELCOME":  int(dave.GatewayBinaryOpcodeCommitWelcome),
		"ANNOUNCE_COMMIT": int(dave.GatewayBinaryOpcodeAnnounceCommit),
		"WELCOME":         int(dave.GatewayBinaryOpcodeWelcome),
	}))

	setModuleFunc(module, "createSession", func(_ js.Value, args []js.Value) any {
		if len(args) < 3 {
			return throw(errors.New("createSession requires protocolVersion, userId, and channelId"))
		}

		keyPair, err := keyPairFromJS(argsAt(args, 3))
		if err != nil {
			return throw(err)
		}

		session, err := dave.NewDAVESession(
			uint16(args[0].Int()),
			args[1].String(),
			args[2].String(),
			keyPair,
		)
		if err != nil {
			return throw(err)
		}

		return newJSSession(session)
	})
	setModuleFunc(module, "generateP256Keypair", func(_ js.Value, _ []js.Value) any {
		keyPair, err := dave.GenerateP256Keypair()
		if err != nil {
			return throw(err)
		}
		return signingKeyPairToJS(keyPair)
	})
	setModuleFunc(module, "generateDisplayableCode", func(_ js.Value, args []js.Value) any {
		if len(args) < 3 {
			return throw(errors.New("generateDisplayableCode requires data, desiredLength, and groupSize"))
		}
		data, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		code, err := dave.GenerateDisplayableCode(data, uint32(args[1].Int()), uint32(args[2].Int()))
		if err != nil {
			return throw(err)
		}
		return code
	})
	setModuleFunc(module, "generateKeyFingerprint", func(_ js.Value, args []js.Value) any {
		if len(args) < 3 {
			return throw(errors.New("generateKeyFingerprint requires version, key, and userId"))
		}
		key, err := bytesFromJS(args[1])
		if err != nil {
			return throw(err)
		}
		userID, err := parseUint64(args[2].String())
		if err != nil {
			return throw(err)
		}
		fingerprint, err := dave.GenerateKeyFingerprint(uint16(args[0].Int()), key, userID)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(fingerprint)
	})
	setModuleFunc(module, "generatePairwiseFingerprint", func(_ js.Value, args []js.Value) any {
		if len(args) < 5 {
			return throw(errors.New("generatePairwiseFingerprint requires version, localKey, localUserId, remoteKey, and remoteUserId"))
		}
		localKey, err := bytesFromJS(args[1])
		if err != nil {
			return throw(err)
		}
		remoteKey, err := bytesFromJS(args[3])
		if err != nil {
			return throw(err)
		}
		localUserID, err := parseUint64(args[2].String())
		if err != nil {
			return throw(err)
		}
		remoteUserID, err := parseUint64(args[4].String())
		if err != nil {
			return throw(err)
		}
		fingerprint, err := dave.GeneratePairwiseFingerprint(
			uint16(args[0].Int()),
			localKey,
			localUserID,
			remoteKey,
			remoteUserID,
		)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(fingerprint)
	})
	setModuleFunc(module, "shouldBeCommitter", func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return throw(errors.New("shouldBeCommitter requires selfUserId"))
		}
		userIDs, err := stringsFromJS(argsAt(args, 1))
		if err != nil {
			return throw(err)
		}
		return dave.ShouldBeCommitter(args[0].String(), userIDs)
	})
	setModuleFunc(module, "parseGatewayBinaryPacket", func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return throw(errors.New("parseGatewayBinaryPacket requires a packet"))
		}
		packet, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		parsed, err := dave.ParseGatewayBinaryPacket(packet)
		if err != nil {
			return throw(err)
		}
		return gatewayPacketToJS(parsed)
	})
	setModuleFunc(module, "encodeKeyPackagePacket", func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return throw(errors.New("encodeKeyPackagePacket requires a key package"))
		}
		keyPackage, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		packet, err := dave.EncodeKeyPackagePacket(keyPackage)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(packet)
	})
	setModuleFunc(module, "encodeExternalSenderPackage", func(_ js.Value, args []js.Value) any {
		if len(args) < 2 {
			return throw(errors.New("encodeExternalSenderPackage requires a signature key and userId"))
		}
		signatureKey, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		packet, err := dave.EncodeExternalSenderPackage(signatureKey, args[1].String())
		if err != nil {
			return throw(err)
		}
		return bytesToJS(packet)
	})
	setModuleFunc(module, "encodeMLSMessageVector", func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return throw(errors.New("encodeMLSMessageVector requires at least one MLS message"))
		}

		var messages [][]byte
		switch {
		case args[0].Type() == js.TypeObject && !args[0].IsNull() && !args[0].IsUndefined() && args[0].InstanceOf(js.Global().Get("Array")):
			length := args[0].Length()
			messages = make([][]byte, 0, length)
			for i := 0; i < length; i++ {
				message, err := bytesFromJS(args[0].Index(i))
				if err != nil {
					return throw(err)
				}
				messages = append(messages, message)
			}
		default:
			messages = make([][]byte, 0, len(args))
			for _, arg := range args {
				message, err := bytesFromJS(arg)
				if err != nil {
					return throw(err)
				}
				messages = append(messages, message)
			}
		}

		vector, err := dave.EncodeMLSMessageVector(messages...)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(vector)
	})
	setModuleFunc(module, "encodeCommitWelcomePacket", func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return throw(errors.New("encodeCommitWelcomePacket requires a commit"))
		}
		commit, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		welcome, err := bytesFromJS(argsAt(args, 1))
		if err != nil {
			return throw(err)
		}
		packet, err := dave.EncodeCommitWelcomePacket(commit, welcome)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(packet)
	})

	js.Global().Set("GoDave", module)
	select {}
}

func newJSSession(session *dave.DAVESession) js.Value {
	sessionMu.Lock()
	nextSessionID++
	id := nextSessionID
	wrapper := &jsSession{
		id:      id,
		session: session,
	}
	sessions[id] = wrapper
	sessionMu.Unlock()

	obj := js.Global().Get("Object").New()
	obj.Set("id", id)
	wrapper.setMethod(obj, "dispose", func(_ js.Value, _ []js.Value) any {
		wrapper.release()
		return nil
	})
	wrapper.setMethod(obj, "getState", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		return sessionStateToJS(wrapper.session)
	})
	wrapper.setMethod(obj, "getEpochAuthenticator", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		return optionalBytesToJS(wrapper.session.GetEpochAuthenticator())
	})
	wrapper.setMethod(obj, "reinit", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 3 {
			return throw(errors.New("reinit requires protocolVersion, userId, and channelId"))
		}
		keyPair, err := keyPairFromJS(argsAt(args, 3))
		if err != nil {
			return throw(err)
		}
		if err := wrapper.session.Reinit(uint16(args[0].Int()), args[1].String(), args[2].String(), keyPair); err != nil {
			return throw(err)
		}
		return nil
	})
	wrapper.setMethod(obj, "reset", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if err := wrapper.session.Reset(); err != nil {
			return throw(err)
		}
		return nil
	})
	wrapper.setMethod(obj, "setExternalSender", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("setExternalSender requires data"))
		}
		data, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		if err := wrapper.session.SetExternalSender(data); err != nil {
			return throw(err)
		}
		return nil
	})
	wrapper.setMethod(obj, "getSerializedKeyPackage", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		keyPackage, err := wrapper.session.GetSerializedKeyPackage()
		if err != nil {
			return throw(err)
		}
		return bytesToJS(keyPackage)
	})
	wrapper.setMethod(obj, "getKeyPackagePacket", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		packet, err := wrapper.session.GetKeyPackagePacket()
		if err != nil {
			return throw(err)
		}
		return bytesToJS(packet)
	})
	wrapper.setMethod(obj, "createAddProposal", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("createAddProposal requires a key package"))
		}
		keyPackage, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		proposal, err := wrapper.session.CreateAddProposal(keyPackage)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(proposal)
	})
	wrapper.setMethod(obj, "processProposals", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 2 {
			return throw(errors.New("processProposals requires operationType and payload"))
		}
		payload, err := bytesFromJS(args[1])
		if err != nil {
			return throw(err)
		}
		userIDs, err := stringsFromJS(argsAt(args, 2))
		if err != nil {
			return throw(err)
		}
		commitWelcome, err := wrapper.session.ProcessProposals(dave.ProposalsOperationType(args[0].Int()), payload, userIDs)
		if err != nil {
			return throw(err)
		}
		return commitWelcomeToJS(commitWelcome)
	})
	wrapper.setMethod(obj, "processWelcome", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("processWelcome requires a welcome"))
		}
		welcome, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		if err := wrapper.session.ProcessWelcome(welcome); err != nil {
			return throw(err)
		}
		return nil
	})
	wrapper.setMethod(obj, "processCommit", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("processCommit requires a commit"))
		}
		commit, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		if err := wrapper.session.ProcessCommit(commit); err != nil {
			return throw(err)
		}
		return nil
	})
	wrapper.setMethod(obj, "handleGatewayBinaryPacket", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("handleGatewayBinaryPacket requires a packet"))
		}
		packet, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		userIDs, err := stringsFromJS(argsAt(args, 1))
		if err != nil {
			return throw(err)
		}
		result, err := wrapper.session.HandleGatewayBinaryPacket(packet, userIDs)
		if err != nil {
			return throw(err)
		}
		return gatewayResultToJS(result)
	})
	wrapper.setMethod(obj, "handleGatewayBinaryMessage", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 3 {
			return throw(errors.New("handleGatewayBinaryMessage requires sequence, opcode, and payload"))
		}
		payload, err := bytesFromJS(args[2])
		if err != nil {
			return throw(err)
		}
		userIDs, err := stringsFromJS(argsAt(args, 3))
		if err != nil {
			return throw(err)
		}
		result, err := wrapper.session.HandleGatewayBinaryMessage(
			uint16(args[0].Int()),
			dave.GatewayBinaryOpcode(args[1].Int()),
			payload,
			userIDs,
		)
		if err != nil {
			return throw(err)
		}
		return gatewayResultToJS(result)
	})
	wrapper.setMethod(obj, "getVerificationCode", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("getVerificationCode requires a userId"))
		}
		code, err := wrapper.session.GetVerificationCode(args[0].String())
		if err != nil {
			return throw(err)
		}
		return code
	})
	wrapper.setMethod(obj, "getPairwiseFingerprint", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 2 {
			return throw(errors.New("getPairwiseFingerprint requires version and userId"))
		}
		fingerprint, err := wrapper.session.GetPairwiseFingerprint(uint16(args[0].Int()), args[1].String())
		if err != nil {
			return throw(err)
		}
		return bytesToJS(fingerprint)
	})
	wrapper.setMethod(obj, "encrypt", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 3 {
			return throw(errors.New("encrypt requires mediaType, codec, and packet"))
		}
		packet, err := bytesFromJS(args[2])
		if err != nil {
			return throw(err)
		}
		encrypted, err := wrapper.session.Encrypt(
			dave.MediaType(args[0].Int()),
			dave.Codec(args[1].Int()),
			packet,
		)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(encrypted)
	})
	wrapper.setMethod(obj, "encryptOpus", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("encryptOpus requires a packet"))
		}
		packet, err := bytesFromJS(args[0])
		if err != nil {
			return throw(err)
		}
		encrypted, err := wrapper.session.EncryptOpus(packet)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(encrypted)
	})
	wrapper.setMethod(obj, "getEncryptionStats", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		mediaType := dave.MediaTypeAudio
		if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
			mediaType = dave.MediaType(args[0].Int())
		}
		return encryptionStatsToJS(wrapper.session.GetEncryptionStats(mediaType))
	})
	wrapper.setMethod(obj, "decrypt", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 3 {
			return throw(errors.New("decrypt requires userId, mediaType, and packet"))
		}
		packet, err := bytesFromJS(args[2])
		if err != nil {
			return throw(err)
		}
		decrypted, err := wrapper.session.Decrypt(args[0].String(), dave.MediaType(args[1].Int()), packet)
		if err != nil {
			return throw(err)
		}
		return bytesToJS(decrypted)
	})
	wrapper.setMethod(obj, "getDecryptionStats", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("getDecryptionStats requires a userId"))
		}
		mediaType := dave.MediaTypeAudio
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			mediaType = dave.MediaType(args[1].Int())
		}
		stats, err := wrapper.session.GetDecryptionStats(args[0].String(), mediaType)
		if err != nil {
			return throw(err)
		}
		return decryptionStatsToJS(stats)
	})
	wrapper.setMethod(obj, "getUserIds", func(_ js.Value, _ []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		return stringsToJS(wrapper.session.GetUserIDs())
	})
	wrapper.setMethod(obj, "canPassthrough", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("canPassthrough requires a userId"))
		}
		return wrapper.session.CanPassthrough(args[0].String())
	})
	wrapper.setMethod(obj, "setPassthroughMode", func(_ js.Value, args []js.Value) any {
		if err := wrapper.requireSession(); err != nil {
			return throw(err)
		}
		if len(args) < 1 {
			return throw(errors.New("setPassthroughMode requires a boolean"))
		}
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			wrapper.session.SetPassthroughMode(args[0].Bool(), uint32(args[1].Int()))
			return nil
		}
		wrapper.session.SetPassthroughMode(args[0].Bool())
		return nil
	})

	return obj
}

func (s *jsSession) setMethod(obj js.Value, name string, fn func(this js.Value, args []js.Value) any) {
	method := guardedJSFunc(fn)
	s.funcs = append(s.funcs, method)
	obj.Set(name, method)
}

func (s *jsSession) requireSession() error {
	if s == nil || s.session == nil {
		return errors.New("session is disposed")
	}
	return nil
}

func (s *jsSession) release() {
	sessionMu.Lock()
	delete(sessions, s.id)
	sessionMu.Unlock()

	for _, fn := range s.funcs {
		fn.Release()
	}
	s.funcs = nil
	s.session = nil
}

func setModuleFunc(obj js.Value, name string, fn func(this js.Value, args []js.Value) any) {
	value := guardedJSFunc(fn)
	moduleFuncs = append(moduleFuncs, value)
	obj.Set(name, value)
}

func argsAt(args []js.Value, index int) js.Value {
	if index >= len(args) {
		return js.Undefined()
	}
	return args[index]
}

func guardedJSFunc(fn func(this js.Value, args []js.Value) any) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) (result any) {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = panicResult(recovered)
			}
		}()
		return fn(this, args)
	})
}

func throw(err error) any {
	return errorResult(err, false)
}

func panicResult(recovered any) any {
	switch value := recovered.(type) {
	case error:
		return errorResult(value, true)
	case string:
		return errorResult(errors.New(value), true)
	default:
		return errorResult(fmt.Errorf("%v", value), true)
	}
}

func errorResult(err error, panicked bool) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set(jsErrorMarker, true)
	obj.Set("message", err.Error())
	if panicked {
		obj.Set("name", "GoDavePanic")
	} else {
		obj.Set("name", "GoDaveError")
	}
	obj.Set("panic", panicked)
	return obj
}

func parseUint64(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse uint64 %q: %w", value, err)
	}
	return parsed, nil
}

func bytesFromJS(value js.Value) ([]byte, error) {
	if value.IsNull() || value.IsUndefined() {
		return nil, nil
	}

	uint8Array := js.Global().Get("Uint8Array")
	if value.InstanceOf(uint8Array) {
		data := make([]byte, value.Get("byteLength").Int())
		js.CopyBytesToGo(data, value)
		return data, nil
	}

	arrayBuffer := js.Global().Get("ArrayBuffer")
	if value.InstanceOf(arrayBuffer) {
		view := uint8Array.New(value)
		data := make([]byte, view.Get("byteLength").Int())
		js.CopyBytesToGo(data, view)
		return data, nil
	}

	return nil, fmt.Errorf("expected Uint8Array or ArrayBuffer")
}

func bytesToJS(data []byte) js.Value {
	array := js.Global().Get("Uint8Array").New(len(data))
	if len(data) > 0 {
		js.CopyBytesToJS(array, data)
	}
	return array
}

func optionalBytesToJS(data []byte) js.Value {
	if len(data) == 0 {
		return js.Null()
	}
	return bytesToJS(data)
}

func stringsFromJS(value js.Value) ([]string, error) {
	if value.IsNull() || value.IsUndefined() {
		return nil, nil
	}

	length := value.Length()
	items := make([]string, length)
	for i := 0; i < length; i++ {
		items[i] = value.Index(i).String()
	}
	return items, nil
}

func stringsToJS(values []string) js.Value {
	array := js.Global().Get("Array").New(len(values))
	for index, value := range values {
		array.SetIndex(index, value)
	}
	return array
}

func keyPairFromJS(value js.Value) (*dave.SigningKeyPair, error) {
	if value.IsNull() || value.IsUndefined() {
		return nil, nil
	}

	privateKey, err := bytesFromJS(value.Get("private"))
	if err != nil {
		return nil, fmt.Errorf("parse signing private key: %w", err)
	}
	publicKey, err := bytesFromJS(value.Get("public"))
	if err != nil {
		return nil, fmt.Errorf("parse signing public key: %w", err)
	}

	return &dave.SigningKeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

func signingKeyPairToJS(pair *dave.SigningKeyPair) js.Value {
	if pair == nil {
		return js.Null()
	}
	return mapObject(map[string]any{
		"private": bytesToJS(pair.Private),
		"public":  bytesToJS(pair.Public),
	})
}

func sessionStateToJS(session *dave.DAVESession) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("protocolVersion", session.ProtocolVersion())
	obj.Set("userId", session.UserID())
	obj.Set("channelId", session.ChannelID())
	if ownLeafIndex, ok := session.OwnLeafIndex(); ok {
		obj.Set("ownLeafIndex", ownLeafIndex)
		obj.Set("epoch", session.Epoch())
	} else {
		obj.Set("ownLeafIndex", js.Null())
		obj.Set("epoch", js.Null())
	}
	obj.Set("ciphersuite", session.Ciphersuite())
	obj.Set("status", int(session.Status()))
	obj.Set("ready", session.Ready())
	obj.Set("voicePrivacyCode", session.VoicePrivacyCode())
	obj.Set("userIds", stringsToJS(session.GetUserIDs()))
	return obj
}

func commitWelcomeToJS(value *dave.CommitWelcome) js.Value {
	if value == nil {
		return mapObject(map[string]any{
			"commit":  js.Null(),
			"welcome": js.Null(),
		})
	}
	return mapObject(map[string]any{
		"commit":  optionalBytesToJS(value.Commit),
		"welcome": optionalBytesToJS(value.Welcome),
	})
}

func gatewayPacketToJS(packet *dave.GatewayBinaryPacket) js.Value {
	if packet == nil {
		return js.Null()
	}
	return mapObject(map[string]any{
		"sequence": packet.Sequence,
		"opcode":   int(packet.Opcode),
		"payload":  bytesToJS(packet.Payload),
	})
}

func gatewayResultToJS(result *dave.GatewayBinaryResult) js.Value {
	if result == nil {
		return js.Null()
	}

	obj := js.Global().Get("Object").New()
	obj.Set("sequence", result.Sequence)
	obj.Set("opcode", int(result.Opcode))
	obj.Set("keyPackage", optionalBytesToJS(result.KeyPackage))
	obj.Set("keyPackagePacket", optionalBytesToJS(result.KeyPackagePacket))
	obj.Set("commit", optionalBytesToJS(result.Commit))
	obj.Set("welcome", optionalBytesToJS(result.Welcome))
	obj.Set("commitWelcomePacket", optionalBytesToJS(result.CommitWelcomePacket))
	if result.TransitionID != nil {
		obj.Set("transitionId", *result.TransitionID)
	} else {
		obj.Set("transitionId", js.Null())
	}
	obj.Set("sendTransitionReady", result.SendTransitionReady)
	return obj
}

func encryptionStatsToJS(stats dave.EncryptionStats) js.Value {
	return mapObject(map[string]any{
		"successes":   stats.Successes,
		"failures":    stats.Failures,
		"duration":    stats.Duration,
		"attempts":    stats.Attempts,
		"maxAttempts": stats.MaxAttempts,
	})
}

func decryptionStatsToJS(stats dave.DecryptionStats) js.Value {
	return mapObject(map[string]any{
		"successes":    stats.Successes,
		"failures":     stats.Failures,
		"duration":     stats.Duration,
		"attempts":     stats.Attempts,
		"passthroughs": stats.Passthroughs,
	})
}

func mapObject(values map[string]any) js.Value {
	obj := js.Global().Get("Object").New()
	for key, value := range values {
		obj.Set(key, value)
	}
	return obj
}
