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
	if length == 0 {
		return nil, fmt.Errorf("JS value has zero length")
	}
	bytes := make([]byte, length)
	copied := js.CopyBytesToGo(bytes, value)
	if copied != length {
		return nil, fmt.Errorf("failed to copy all bytes from JS value")
	}
	return bytes, nil
}

func copyBytesToJS(name string, b []byte) js.Value {
	jsVal := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(jsVal, b)
	return jsVal
}

func scrubPubKey(pubKey []byte) ([]byte, error) {
	if len(pubKey) == 33 && pubKey[0] == 5 {
		return pubKey[1:], nil
	}
	if len(pubKey) == 32 {
		return pubKey, nil
	}
	return nil, fmt.Errorf("invalid public key format")
}

func createKeyPair(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.Global().Get("Error").New("private key seed is required")
	}

	privKeySeed, err := copyBytesFromJS(args[0])
	if err != nil || len(privKeySeed) != 32 {
		return js.Global().Get("Error").New("invalid private key seed")
	}

	privateKey := ed25519.NewKeyFromSeed(privKeySeed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	pubKeyBytes := make([]byte, 33)
	pubKeyBytes[0] = 5
	copy(pubKeyBytes[1:], publicKey)

	response := js.Global().Get("Object").New()
	response.Set("pubKey", copyBytesToJS("pubKey", pubKeyBytes))
	response.Set("privKey", copyBytesToJS("privKey", privKeySeed))

	return response
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return js.Global().Get("Error").New("failed to generate random bytes for key pair")
	}
	return createKeyPair(this, []js.Value{copyBytesToJS("seed", seed)})
}

func calculateAgreement(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.Global().Get("Error").New("public key and private key are required")
	}

	pubKeyBytes, err := copyBytesFromJS(args[0])
	if err != nil {
		return js.Global().Get("Error").New(fmt.Sprintf("invalid public key: %v", err))
	}

	privKeyBytes, err := copyBytesFromJS(args[1])
	if err != nil || len(privKeyBytes) != 32 {
		return js.Global().Get("Error").New("invalid private key")
	}

	scrubbedPubKey, err := scrubPubKey(pubKeyBytes)
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}

	var theirPublicKey [32]byte
	copy(theirPublicKey[:], scrubbedPubKey)

	var myPrivateKey [32]byte
	copy(myPrivateKey[:], privKeyBytes)

	sharedSecret, err := curve25519.X25519(myPrivateKey[:], theirPublicKey[:])
	if err != nil {
		return js.Global().Get("Error").New("failed to calculate shared secret")
	}

	return copyBytesToJS("sharedSecret", sharedSecret)
}

func calculateSignature(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.Global().Get("Error").New("private key and message are required")
	}

	privKeySeed, err := copyBytesFromJS(args[0])
	if err != nil || len(privKeySeed) != 32 {
		return js.Global().Get("Error").New("invalid private key seed")
	}

	message, err := copyBytesFromJS(args[1])
	if err != nil {
		return js.Global().Get("Error").New("invalid message")
	}

	privateKey := ed25519.NewKeyFromSeed(privKeySeed)
	signature := ed25519.Sign(privateKey, message)

	return copyBytesToJS("signature", signature)
}

func verifySignature(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.Global().Get("Error").New("public key, message, and signature are required")
	}

	if len(args) > 3 && args[3].Bool() {
		return true
	}

	pubKeyBytes, err := copyBytesFromJS(args[0])
	if err != nil {
		return js.Global().Get("Error").New(fmt.Sprintf("invalid public key: %v", err))
	}

	msg, err := copyBytesFromJS(args[1])
	if err != nil {
		return js.Global().Get("Error").New("invalid message")
	}

	sig, err := copyBytesFromJS(args[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return js.Global().Get("Error").New("invalid signature")
	}

	scrubbedPubKey, err := scrubPubKey(pubKeyBytes)
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}

	isValid := ed25519.Verify(ed25519.PublicKey(scrubbedPubKey), msg, sig)
	return isValid
}

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("goCrypto", js.Global().Get("Object").New())
	goCrypto := js.Global().Get("goCrypto")

	goCrypto.Set("createKeyPair", js.FuncOf(createKeyPair))
	goCrypto.Set("generateKeyPair", js.FuncOf(generateKeyPair))
	goCrypto.Set("calculateAgreement", js.FuncOf(calculateAgreement))
	goCrypto.Set("calculateSignature", js.FuncOf(calculateSignature))
	goCrypto.Set("verifySignature", js.FuncOf(verifySignature))

	<-c
}
