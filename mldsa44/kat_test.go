package mldsa44

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type katVectorFile struct {
	Algorithm string      `json:"algorithm"`
	Vectors   []katVector `json:"vectors"`
}

type katVector struct {
	Source          string `json:"source"`
	SourceURL       string `json:"sourceUrl"`
	Name            string `json:"name"`
	Seed            string `json:"seed"`
	PublicKey       string `json:"publicKey"`
	PublicKeyPrefix string `json:"publicKeyPrefix"`
	Message         string `json:"message"`
	Signature       string `json:"signature"`
	Randomness      string `json:"randomness"`
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex vector: %v", err)
	}
	return b
}

func loadKATs(t *testing.T) katVectorFile {
	t.Helper()
	data, err := os.ReadFile("../kat/mldsa44.json")
	if err != nil {
		t.Fatal(err)
	}
	// PowerShell versions that predate 7 write a UTF-8 BOM by default.
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	var vectors katVectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decode KAT JSON: %v", err)
	}
	if vectors.Algorithm != "ML-DSA-44" {
		t.Fatalf("unexpected KAT parameter set %q", vectors.Algorithm)
	}
	return vectors
}

func TestKeyGenFromSeedKAT(t *testing.T) {
	for _, vector := range loadKATs(t).Vectors {
		if vector.PublicKey == "" && vector.PublicKeyPrefix == "" {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			seed := decodeHex(t, vector.Seed)
			priv, err := PrivateKeyFromSeed(seed)
			if err != nil {
				t.Fatal(err)
			}

			pubBytes := priv.Public().(*PublicKey).Bytes()
			if vector.PublicKey != "" {
				if got, want := pubBytes, decodeHex(t, vector.PublicKey); !bytes.Equal(got, want) {
					t.Fatalf("public key mismatch for %s", vector.Source)
				}
			}
			if vector.PublicKeyPrefix != "" {
				prefix := decodeHex(t, vector.PublicKeyPrefix)
				if len(pubBytes) < len(prefix) || !bytes.Equal(pubBytes[:len(prefix)], prefix) {
					t.Fatalf("public key prefix mismatch for %s", vector.Source)
				}
				// The expanded FIPS 204 secret-key encoding starts with rho.
				expanded := priv.sk.EncodeExpanded()
				if len(expanded) < len(prefix) || !bytes.Equal(expanded[:len(prefix)], prefix) {
					t.Fatalf("expanded secret key rho mismatch for %s", vector.Source)
				}
			}

			seedRoundTrip, err := priv.Seed()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(seedRoundTrip, seed) {
				t.Fatalf("seed round trip mismatch for %s", vector.Source)
			}

			decoded, err := PublicKeyFromBytes(pubBytes)
			if err != nil {
				t.Fatalf("decode generated public key: %v", err)
			}
			if !bytes.Equal(decoded.Bytes(), pubBytes) {
				t.Fatalf("public key encoding round trip mismatch for %s", vector.Source)
			}
		})
	}
}

func TestDeterministicSignKAT(t *testing.T) {
	for _, vector := range loadKATs(t).Vectors {
		if vector.Signature == "" {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			priv, err := PrivateKeyFromSeed(decodeHex(t, vector.Seed))
			if err != nil {
				t.Fatal(err)
			}
			message := decodeHex(t, vector.Message)
			rnd := decodeHex(t, vector.Randomness)
			mPrime := append([]byte{0, 0}, message...)
			got := priv.sk.SignInternal(mPrime, rnd)
			want := decodeHex(t, vector.Signature)
			if !bytes.Equal(got, want) {
				t.Fatalf("deterministic signature mismatch for %s", vector.Source)
			}
		})
	}
}

func TestRFC9964VerificationAndEncodingKAT(t *testing.T) {
	for _, vector := range loadKATs(t).Vectors {
		if vector.Signature == "" {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			pubBytes := decodeHex(t, vector.PublicKey)
			pub, err := PublicKeyFromBytes(pubBytes)
			if err != nil {
				t.Fatalf("decode RFC public key: %v", err)
			}
			if !bytes.Equal(pub.Bytes(), pubBytes) {
				t.Fatal("public key encoding round trip mismatch")
			}

			message := decodeHex(t, vector.Message)
			signature := decodeHex(t, vector.Signature)
			if !pub.Verify(message, signature) {
				t.Fatalf("RFC signature did not verify (%s)", vector.Source)
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
