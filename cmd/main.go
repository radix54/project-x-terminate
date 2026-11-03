package main

import (
	"ml-dsa/internal"
	"ml-dsa/internal/params"
	"ml-dsa/mldsa44"
)

const message string = "Please, give us easier exercises."

func main() {
	// Key generation
	publicKey, privateKey, err := mldsa44.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	// Signing a message
	signature, err := privateKey.Sign([]byte(message))
	if err != nil {
		panic(err)
	}
	// Verifying the signature
	valid := publicKey.Verify([]byte(message), signature)
	if valid {
		println("Signature is valid.")
	} else {
		panic("Signature is invalid.")
	}

	// Exercise the internal key decoding, signing, and public-key recomputation paths.
	internalSigningKey, internalVerifyingKey, err := internal.GenerateKeyPair(params.MLDSA44Cfg)
	if err != nil {
		panic(err)
	}
	decodedSigningKey, err := internal.SkDecode(
		params.MLDSA44Cfg,
		internalSigningKey.EncodeExpanded(),
	)
	if err != nil {
		panic(err)
	}
	mPrime := append([]byte{0, 0}, []byte(message)...)
	internalSignature := decodedSigningKey.SignInternal(mPrime, make([]byte, 32))
	valid = internalVerifyingKey.VerifyInternal(mPrime, internalSignature)
	if !valid {
		panic("internal signature is invalid.")
	}
	println("Internal signature is valid.")
	if _, err := mldsa44.PublicKeyFromBytes(publicKey.Bytes()); err != nil {
		panic(err)
	}
}
