package dave

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type hashRatchet struct {
	nextSecret     []byte
	nextGeneration uint32
	cache          map[uint32]ratchetMaterial
}

type ratchetMaterial struct {
	key   []byte
	nonce []byte
}

func newHashRatchet(secret []byte) *hashRatchet {
	cloned := append([]byte(nil), secret...)
	return &hashRatchet{
		nextSecret: cloned,
		cache:      make(map[uint32]ratchetMaterial),
	}
}

func (r *hashRatchet) get(generation uint32) ([]byte, []byte, error) {
	if material, ok := r.cache[generation]; ok {
		return append([]byte(nil), material.key...), append([]byte(nil), material.nonce...), nil
	}
	if r.nextGeneration > generation {
		return nil, nil, fmt.Errorf("generation %d already expired", generation)
	}

	for r.nextGeneration <= generation {
		if err := r.advance(); err != nil {
			return nil, nil, err
		}
	}

	material := r.cache[generation]
	return append([]byte(nil), material.key...), append([]byte(nil), material.nonce...), nil
}

func (r *hashRatchet) erase(generation uint32) {
	delete(r.cache, generation)
}

func (r *hashRatchet) advance() error {
	generation := r.nextGeneration
	key, err := deriveTreeSecret(r.nextSecret, "key", generation, 16)
	if err != nil {
		return err
	}
	nonce, err := deriveTreeSecret(r.nextSecret, "nonce", generation, 12)
	if err != nil {
		return err
	}
	nextSecret, err := deriveTreeSecret(r.nextSecret, "secret", generation, 32)
	if err != nil {
		return err
	}

	r.cache[generation] = ratchetMaterial{key: key, nonce: nonce}
	r.nextSecret = nextSecret
	r.nextGeneration++
	return nil
}

func deriveTreeSecret(secret []byte, label string, generation uint32, length int) ([]byte, error) {
	ctx := make([]byte, 4)
	binary.BigEndian.PutUint32(ctx, generation)
	return expandWithLabel(secret, label, ctx, length)
}

func expandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	info, err := marshalKDFLabel(label, context, length)
	if err != nil {
		return nil, err
	}
	return hkdfExpand(secret, info, length), nil
}

func marshalKDFLabel(label string, context []byte, length int) ([]byte, error) {
	out := make([]byte, 0, 2+1+len("MLS 1.0 ")+len(label)+1+len(context))
	out = binary.BigEndian.AppendUint16(out, uint16(length))

	fullLabel := []byte("MLS 1.0 " + label)
	if len(fullLabel) > 255 || len(context) > 255 {
		return nil, fmt.Errorf("kdf label too large")
	}
	out = append(out, byte(len(fullLabel)))
	out = append(out, fullLabel...)
	out = append(out, byte(len(context)))
	out = append(out, context...)
	return out, nil
}

func hkdfExpand(prk []byte, info []byte, length int) []byte {
	var (
		okm []byte
		t   []byte
	)

	for counter := byte(1); len(okm) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}

	return append([]byte(nil), okm[:length]...)
}
