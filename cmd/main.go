package main

import "ml-dsa/mldsa44"

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
}
