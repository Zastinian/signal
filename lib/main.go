//go:build js && wasm

package main

import (
	"crypto/rand"
	"fmt"
	"syscall/js"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func copyBytesFromJS(value js.Value) ([]byte, error) {
	length := value.Get("length").Int()
	bytes := make([]byte, length)
	copied := js.CopyBytesToGo(bytes, value)
	if copied != length {
		return nil, fmt.Errorf("failed to copy bytes from JS")
	}
	return bytes, nil
}

func createKeyPair(this js.Value, args []js.Value) interface{} {
	privKeySeed, err := copyBytesFromJS(args[0])
	if err != nil || len(privKeySeed) != 32 {
		return js.Global().Get("Error").New("Invalid private key seed")
	}

	privateKey := ed25519.NewKeyFromSeed(privKeySeed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	pubKeyBytes := make([]byte, 33)
	pubKeyBytes[0] = 5
	copy(pubKeyBytes[1:], publicKey)

	response := js.Global().Get("Object").New()

	pubKeyJS := js.Global().Get("Uint8Array").New(len(pubKeyBytes))
	js.CopyBytesToJS(pubKeyJS, pubKeyBytes)
	response.Set("pubKey", pubKeyJS)

	privKeyJS := js.Global().Get("Uint8Array").New(32)
	js.CopyBytesToJS(privKeyJS, privKeySeed)
	response.Set("privKey", privKeyJS)

	return response
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return js.Global().Get("Error").New("Failed to generate random bytes")
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	pubKeyBytes := make([]byte, 33)
	pubKeyBytes[0] = 5
	copy(pubKeyBytes[1:], publicKey)

	response := js.Global().Get("Object").New()

	pubKeyJS := js.Global().Get("Uint8Array").New(len(pubKeyBytes))
	js.CopyBytesToJS(pubKeyJS, pubKeyBytes)
	response.Set("pubKey", pubKeyJS)

	privKeyJS := js.Global().Get("Uint8Array").New(32)
	js.CopyBytesToJS(privKeyJS, seed)
	response.Set("privKey", privKeyJS)

	return response
}

func calculateAgreement(this js.Value, args []js.Value) interface{} {
	pubKey, err := copyBytesFromJS(args[0])
	if err != nil {
		return js.Global().Get("Error").New("Invalid public key")
	}

	privKeySeed, err := copyBytesFromJS(args[1])
	if err != nil || len(privKeySeed) != 32 {
		return js.Global().Get("Error").New("Invalid private key")
	}

	var scrubbedPubKey []byte
	if len(pubKey) == 33 && pubKey[0] == 5 {
		scrubbedPubKey = pubKey[1:]
	} else if len(pubKey) == 32 {
		scrubbedPubKey = pubKey
	} else {
		return js.Global().Get("Error").New("Invalid public key format")
	}

	if len(scrubbedPubKey) != 32 {
		return js.Global().Get("Error").New("Invalid public key length")
	}

	privateKey := ed25519.NewKeyFromSeed(privKeySeed)
	var x25519Private [32]byte
	copy(x25519Private[:], privateKey.Seed())

	var x25519Public [32]byte
	copy(x25519Public[:], scrubbedPubKey)

	sharedSecret, err := curve25519.X25519(x25519Private[:], x25519Public[:])
	if err != nil {
		return js.Global().Get("Error").New("Failed to calculate agreement")
	}

	result := js.Global().Get("Uint8Array").New(len(sharedSecret))
	js.CopyBytesToJS(result, sharedSecret)
	return result
}

func calculateSignature(this js.Value, args []js.Value) interface{} {
	privKeySeed, err := copyBytesFromJS(args[0])
	if err != nil || len(privKeySeed) != 32 {
		return js.Global().Get("Error").New("Invalid private key")
	}

	message, err := copyBytesFromJS(args[1])
	if err != nil {
		return js.Global().Get("Error").New("Invalid message")
	}

	privateKey := ed25519.NewKeyFromSeed(privKeySeed)

	signature := ed25519.Sign(privateKey, message)

	result := js.Global().Get("Uint8Array").New(len(signature))
	js.CopyBytesToJS(result, signature)
	return result
}

func verifySignature(this js.Value, args []js.Value) interface{} {

	if len(args) > 3 && args[3].Bool() {
		return true
	}

	pubKey, err := copyBytesFromJS(args[0])
	if err != nil {
		return js.Global().Get("Error").New("Invalid public key")
	}

	msg, err := copyBytesFromJS(args[1])
	if err != nil {
		return js.Global().Get("Error").New("Invalid message")
	}

	sig, err := copyBytesFromJS(args[2])
	if err != nil || len(sig) != 64 {
		return js.Global().Get("Error").New("Invalid signature")
	}

	var scrubbedPubKey []byte
	if len(pubKey) == 33 && pubKey[0] == 5 {
		scrubbedPubKey = pubKey[1:]
	} else if len(pubKey) == 32 {
		scrubbedPubKey = pubKey
	} else {
		return js.Global().Get("Error").New("Invalid public key format")
	}

	if len(scrubbedPubKey) != 32 {
		return js.Global().Get("Error").New("Invalid public key length")
	}

	isValid := ed25519.Verify(ed25519.PublicKey(scrubbedPubKey), msg, sig)
	return isValid
}

func main() {
	c := make(chan struct{})

	js.Global().Set("goCrypto", js.Global().Get("Object").New())
	goCrypto := js.Global().Get("goCrypto")

	goCrypto.Set("createKeyPair", js.FuncOf(createKeyPair))
	goCrypto.Set("generateKeyPair", js.FuncOf(generateKeyPair))
	goCrypto.Set("calculateAgreement", js.FuncOf(calculateAgreement))
	goCrypto.Set("calculateSignature", js.FuncOf(calculateSignature))
	goCrypto.Set("verifySignature", js.FuncOf(verifySignature))

	<-c
}
