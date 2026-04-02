package dave

const (
	DAVEProtocolVersion = 1

	userMediaKeyBaseLabel = "Discord Secure Frames v0"

	opusSilencePacket = "\xF8\xFF\xFE"
)

type MediaType uint8

const (
	MediaTypeAudio MediaType = 0
	MediaTypeVideo MediaType = 1
)

type Codec uint8

const (
	CodecUnknown Codec = 0
	CodecOpus    Codec = 1
	CodecVP8     Codec = 2
	CodecVP9     Codec = 3
	CodecH264    Codec = 4
	CodecH265    Codec = 5
	CodecAV1     Codec = 6
)

type ProposalsOperationType uint8

const (
	ProposalsAppend ProposalsOperationType = 0
	ProposalsRevoke ProposalsOperationType = 1
)

type SessionStatus uint8

const (
	SessionStatusInactive         SessionStatus = 0
	SessionStatusPending          SessionStatus = 1
	SessionStatusAwaitingResponse SessionStatus = 2
	SessionStatusActive           SessionStatus = 3
)

type EncryptionStats struct {
	Successes   uint32
	Failures    uint32
	Duration    uint32
	Attempts    uint32
	MaxAttempts uint32
}

type DecryptionStats struct {
	Successes    uint32
	Failures     uint32
	Duration     uint32
	Attempts     uint32
	Passthroughs uint32
}

type CommitWelcome struct {
	Commit  []byte
	Welcome []byte
}
