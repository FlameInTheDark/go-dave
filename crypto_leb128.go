package dave

func leb128Size(value uint64) int {
	size := 1
	for value >= 0x80 {
		size++
		value >>= 7
	}
	return size
}

func writeLEB128(dst []byte, value uint64) int {
	written := 0
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		dst[written] = b
		written++
		if value == 0 {
			return written
		}
	}
}

func readLEB128(src []byte) (value uint64, consumed int, ok bool) {
	for i, b := range src {
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, i + 1, true
		}
		if i == 9 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}
