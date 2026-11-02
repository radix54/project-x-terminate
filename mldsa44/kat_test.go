package mldsa44

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// The JOSE and COSE examples have different envelope fields. These fields are
// common to both and contain the raw ML-DSA inputs and outputs.
type rfc9964Vector struct {
	PrivateSeed  string `json:"priv"`
	RawMessage   string `json:"raw_to_be_signed"`
	RawSignature string `json:"raw_signature"`
	RawPublicKey string `json:"raw_public_key"`
}

const rfc9964VectorFile string = "../kat/rfc9964.json"

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex vector: %v", err)
	}
	return b
}

func loadRFC9964Vectors(t *testing.T) []rfc9964Vector {
	t.Helper()
	data, err := os.ReadFile(rfc9964VectorFile)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	var vectors []rfc9964Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decode file: %v", err)
	}

	// This package implements ML-DSA-44, whose public key encoding is 1312 bytes.
	var mldsa44 []rfc9964Vector
	for _, vector := range vectors {
		if len(vector.RawPublicKey) == 2*1312 && len(vector.PrivateSeed) == 2*32 {
			mldsa44 = append(mldsa44, vector)
		}
	}
	if len(mldsa44) == 0 {
		t.Fatal("file contains no ML-DSA-44 vectors")
	}
	return mldsa44
}

func TestKeyGenFromSeedKAT(t *testing.T) {
	for i, vector := range loadRFC9964Vectors(t) {
		t.Run(fmt.Sprintf("RFC9964_%d", i+1), func(t *testing.T) {
			seed := decodeHex(t, vector.PrivateSeed)
			priv, err := PrivateKeyFromSeed(seed)
			if err != nil {
				t.Fatal(err)
			}

			gotPublicKey := priv.Public().(*PublicKey).Bytes()
			if want := decodeHex(t, vector.RawPublicKey); !bytes.Equal(gotPublicKey, want) {
				t.Fatal("public key mismatch")
			}
			gotSeed, err := priv.Seed()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSeed, seed) {
				t.Fatal("seed round trip mismatch")
			}
			checkPublicKeyEncoding(t, gotPublicKey)
		})
	}
}

func TestDeterministicSignKAT(t *testing.T) {
	for i, vector := range loadRFC9964Vectors(t) {
		t.Run(fmt.Sprintf("RFC9964_%d", i+1), func(t *testing.T) {
			priv, err := PrivateKeyFromSeed(decodeHex(t, vector.PrivateSeed))
			if err != nil {
				t.Fatal(err)
			}
			message := decodeHex(t, vector.RawMessage)
			mPrime := append([]byte{0, 0}, message...)
			got := priv.sk.SignInternal(mPrime, make([]byte, 32))
			if want := decodeHex(t, vector.RawSignature); !bytes.Equal(got, want) {
				t.Fatal("deterministic signature mismatch")
			}
		})
	}
}

func TestRFC9964VerificationAndEncodingKAT(t *testing.T) {
	for i, vector := range loadRFC9964Vectors(t) {
		t.Run(fmt.Sprintf("RFC9964_%d", i+1), func(t *testing.T) {
			publicKeyBytes := decodeHex(t, vector.RawPublicKey)
			pub, err := PublicKeyFromBytes(publicKeyBytes)
			if err != nil {
				t.Fatalf("decode RFC public key: %v", err)
			}
			if !bytes.Equal(pub.Bytes(), publicKeyBytes) {
				t.Fatal("public key encoding round trip mismatch")
			}

			message := decodeHex(t, vector.RawMessage)
			signature := decodeHex(t, vector.RawSignature)
			if !pub.Verify(message, signature) {
				t.Fatal("RFC signature did not verify")
			}

			tamperedMessage := append([]byte(nil), message...)
			tamperedMessage[0] ^= 1
			if pub.Verify(tamperedMessage, signature) {
				t.Fatal("signature verified after message tampering")
			}

			tamperedSignature := append([]byte(nil), signature...)
			tamperedSignature[0] ^= 1
			if pub.Verify(message, tamperedSignature) {
				t.Fatal("tampered signature verified")
			}
		})
	}
}

func checkPublicKeyEncoding(t *testing.T, encoded []byte) {
	t.Helper()
	decoded, err := PublicKeyFromBytes(encoded)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if !bytes.Equal(decoded.Bytes(), encoded) {
		t.Fatal("public key encoding round trip mismatch")
	}
}
