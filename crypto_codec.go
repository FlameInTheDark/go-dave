package dave

import (
	"bytes"
	"fmt"
)

const (
	naluShortStartSequenceSize = 3
	transformPaddingBytes      = 64
)

var naluLongStartCode = []byte{0x00, 0x00, 0x00, 0x01}

func bytesCoveringH264PPS(payload []byte, sizeRemaining int) uint16 {
	const emulationPreventionByte = 0x03

	var (
		payloadBitIndex       uint64
		zeroBitCount          uint64
		parsedExpGolombValues int
	)

	for payloadBitIndex < uint64(sizeRemaining*8) && parsedExpGolombValues < 3 {
		bitIndex := payloadBitIndex % 8
		byteIndex := int(payloadBitIndex / 8)
		payloadByte := payload[byteIndex]

		if bitIndex == 0 && byteIndex >= 2 && payloadByte == emulationPreventionByte && payload[byteIndex-1] == 0 && payload[byteIndex-2] == 0 {
			payloadBitIndex += 8
			continue
		}

		if payloadByte&(1<<(7-bitIndex)) == 0 {
			zeroBitCount++
			payloadBitIndex++
			if zeroBitCount >= 32 {
				return 0
			}
			continue
		}

		parsedExpGolombValues++
		payloadBitIndex = payloadBitIndex + 1 + zeroBitCount
		zeroBitCount = 0
	}

	result := payloadBitIndex/8 + 1
	if result > uint64(^uint16(0)) {
		return 0
	}
	return uint16(result)
}

func nextH26XNALUIndex(buffer []byte, searchStart int) (nalStart int, startCodeSize int, ok bool) {
	if len(buffer) < naluShortStartSequenceSize {
		return 0, 0, false
	}

	for i := searchStart; i < len(buffer)-naluShortStartSequenceSize; {
		switch {
		case buffer[i+2] > 1:
			i += naluShortStartSequenceSize
		case buffer[i+1] != 0:
			i += 2
		case buffer[i] != 0 || buffer[i+2] != 1:
			i++
		default:
			nalStart = i + naluShortStartSequenceSize
			if i >= 1 && buffer[i-1] == 0 {
				return nalStart, 4, true
			}
			return nalStart, 3, true
		}
	}
	return 0, 0, false
}

func processFrameOpus(processor *outboundFrameProcessor, frame []byte) bool {
	processor.addEncryptedBytes(frame)
	return true
}

func processFrameH264(processor *outboundFrameProcessor, frame []byte) bool {
	const (
		nalHeaderTypeMask = 0x1f
		nalTypeSlice      = 1
		nalTypeIDR        = 5
		nalHeaderSize     = 1
	)
	if len(frame) < naluShortStartSequenceSize+nalHeaderSize {
		return false
	}

	nalStart, _, ok := nextH26XNALUIndex(frame, 0)
	for ok {
		if nalStart >= len(frame)-1 {
			break
		}

		nalType := frame[nalStart] & nalHeaderTypeMask
		processor.addUnencryptedBytes(naluLongStartCode)

		nextStart, nextSize, hasNext := nextH26XNALUIndex(frame, nalStart)
		nextNALUStart := len(frame)
		if hasNext {
			nextNALUStart = nextStart - nextSize
		}

		if nalType == nalTypeSlice || nalType == nalTypeIDR {
			payloadStart := nalStart + nalHeaderSize
			ppsBytes := int(bytesCoveringH264PPS(frame[payloadStart:], len(frame)-payloadStart))
			unencryptedEnd := nalStart + nalHeaderSize + ppsBytes
			if unencryptedEnd > nextNALUStart || unencryptedEnd > len(frame) {
				return false
			}
			processor.addUnencryptedBytes(frame[nalStart:unencryptedEnd])
			processor.addEncryptedBytes(frame[unencryptedEnd:nextNALUStart])
		} else {
			processor.addUnencryptedBytes(frame[nalStart:nextNALUStart])
		}

		nalStart, _, ok = nextStart, nextSize, hasNext
	}
	return true
}

func processFrameH265(processor *outboundFrameProcessor, frame []byte) bool {
	const (
		nalHeaderTypeMask = 0x7e
		nalTypeVCLCutoff  = 32
		nalHeaderSize     = 2
	)
	if len(frame) < naluShortStartSequenceSize+nalHeaderSize {
		return false
	}

	nalStart, _, ok := nextH26XNALUIndex(frame, 0)
	for ok {
		if nalStart >= len(frame)-1 {
			break
		}
		nalType := (frame[nalStart] & nalHeaderTypeMask) >> 1
		processor.addUnencryptedBytes(naluLongStartCode)

		nextStart, nextSize, hasNext := nextH26XNALUIndex(frame, nalStart)
		nextNALUStart := len(frame)
		if hasNext {
			nextNALUStart = nextStart - nextSize
		}

		if nalType < nalTypeVCLCutoff {
			if nalStart+nalHeaderSize > nextNALUStart {
				return false
			}
			processor.addUnencryptedBytes(frame[nalStart : nalStart+nalHeaderSize])
			processor.addEncryptedBytes(frame[nalStart+nalHeaderSize : nextNALUStart])
		} else {
			processor.addEncryptedBytes(frame[nalStart:nextNALUStart])
		}

		nalStart, _, ok = nextStart, nextSize, hasNext
	}
	return true
}

func processFrameVP8(processor *outboundFrameProcessor, frame []byte) bool {
	if len(frame) == 0 {
		return false
	}
	unencryptedHeaderBytes := 1
	if frame[0]&0x01 == 0 {
		unencryptedHeaderBytes = 10
	}
	if len(frame) < unencryptedHeaderBytes {
		return false
	}
	processor.addUnencryptedBytes(frame[:unencryptedHeaderBytes])
	processor.addEncryptedBytes(frame[unencryptedHeaderBytes:])
	return true
}

func processFrameVP9(processor *outboundFrameProcessor, frame []byte) bool {
	processor.addEncryptedBytes(frame)
	return true
}

func processFrameAV1(processor *outboundFrameProcessor, frame []byte) bool {
	const (
		obuHeaderHasExtensionMask = 0b00000100
		obuHeaderHasSizeMask      = 0b00000010
		obuHeaderTypeMask         = 0b01111000
		obuTypeTemporalDelimiter  = 2
		obuTypeTileList           = 8
		obuTypePadding            = 15
		obuExtensionSizeBytes     = 1
	)

	for i := 0; i < len(frame); {
		obuHeaderIndex := i
		obuHeader := frame[i]
		i++

		obuHasExtension := (obuHeader & obuHeaderHasExtensionMask) != 0
		obuHasSize := (obuHeader & obuHeaderHasSizeMask) != 0
		obuType := (obuHeader & obuHeaderTypeMask) >> 3

		if obuHasExtension {
			i += obuExtensionSizeBytes
		}
		if i >= len(frame) {
			return false
		}

		var (
			obuPayloadSize int
			sizeFieldBytes int
		)
		if obuHasSize {
			size, consumed, ok := readLEB128(frame[i:])
			if !ok {
				return false
			}
			obuPayloadSize = int(size)
			sizeFieldBytes = consumed
			i += consumed
		} else {
			obuPayloadSize = len(frame) - i
		}

		obuPayloadIndex := i
		if i+obuPayloadSize > len(frame) {
			return false
		}
		i += obuPayloadSize

		if obuType == obuTypeTemporalDelimiter || obuType == obuTypeTileList || obuType == obuTypePadding {
			continue
		}

		rewrittenWithoutSize := i == len(frame) && obuHasSize
		if rewrittenWithoutSize {
			obuHeader &^= obuHeaderHasSizeMask
		}

		processor.addUnencryptedBytes([]byte{obuHeader})
		if obuHasExtension {
			processor.addUnencryptedBytes(frame[obuHeaderIndex+1 : obuHeaderIndex+1+obuExtensionSizeBytes])
		}

		if obuHasSize && !rewrittenWithoutSize {
			buf := make([]byte, sizeFieldBytes)
			if writeLEB128(buf, uint64(obuPayloadSize)) != sizeFieldBytes {
				return false
			}
			processor.addUnencryptedBytes(buf)
		}

		processor.addEncryptedBytes(frame[obuPayloadIndex : obuPayloadIndex+obuPayloadSize])
	}
	return true
}

func validateEncryptedFrame(processor *outboundFrameProcessor, frame []byte) bool {
	if processor.frameCodec != CodecH264 && processor.frameCodec != CodecH265 {
		return true
	}

	const padding = naluShortStartSequenceSize - 1
	encryptedSectionStart := 0

	for _, r := range processor.unencryptedRanges {
		if encryptedSectionStart == r.offset {
			encryptedSectionStart += r.size
			continue
		}

		start := encryptedSectionStart - min(encryptedSectionStart, padding)
		end := min(r.offset+padding, len(frame))
		if _, _, ok := nextH26XNALUIndex(frame[start:end], 0); ok {
			return false
		}
		encryptedSectionStart = r.offset + r.size
	}

	if encryptedSectionStart == len(frame) {
		return true
	}

	start := encryptedSectionStart - min(encryptedSectionStart, padding)
	if _, _, ok := nextH26XNALUIndex(frame[start:], 0); ok {
		return false
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func processFrame(processor *outboundFrameProcessor, frame []byte, codec Codec) error {
	processor.reset()
	processor.frameCodec = codec

	var success bool
	switch codec {
	case CodecOpus:
		success = processFrameOpus(processor, frame)
	case CodecH264:
		success = processFrameH264(processor, frame)
	case CodecH265:
		success = processFrameH265(processor, frame)
	case CodecVP8:
		success = processFrameVP8(processor, frame)
	case CodecVP9:
		success = processFrameVP9(processor, frame)
	case CodecAV1:
		success = processFrameAV1(processor, frame)
	default:
		return fmt.Errorf("unsupported codec %d", codec)
	}

	if !success {
		processor.reset()
		processor.frameCodec = codec
		processor.addEncryptedBytes(frame)
	}
	return nil
}

func isOpusSilencePacket(packet []byte) bool {
	return bytes.Equal(packet, []byte(opusSilencePacket))
}
