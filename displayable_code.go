package dave

import (
	"fmt"
	"strings"
)

const maxDisplayableGroupSize = 8

func GenerateDisplayableCode(data []byte, desiredLength, groupSize uint32) (string, error) {
	if len(data) < int(desiredLength) {
		return "", fmt.Errorf("data length %d is smaller than desired length %d", len(data), desiredLength)
	}
	if groupSize == 0 || desiredLength%groupSize != 0 {
		return "", fmt.Errorf("desired length %d must be a multiple of group size %d", desiredLength, groupSize)
	}
	if groupSize > maxDisplayableGroupSize {
		return "", fmt.Errorf("group size %d exceeds maximum %d", groupSize, maxDisplayableGroupSize)
	}

	groupModulus := uint64(1)
	for i := uint32(0); i < groupSize; i++ {
		groupModulus *= 10
	}

	var out strings.Builder
	out.Grow(int(desiredLength))

	for i := uint32(0); i < desiredLength; i += groupSize {
		var groupValue uint64
		for j := uint32(0); j < groupSize; j++ {
			groupValue = (groupValue << 8) | uint64(data[i+j])
		}
		if _, err := fmt.Fprintf(&out, "%0*d", groupSize, groupValue%groupModulus); err != nil {
			return "", fmt.Errorf("write displayable code group: %w", err)
		}
	}

	return out.String(), nil
}
