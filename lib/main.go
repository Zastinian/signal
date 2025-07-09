//go:build js && wasm

package main

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"
	"syscall/js"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func validatePrivKey(privKey []byte) error {
	if len(privKey) != 32 {
		return errors.New("incorrect private key length")
	}
	return nil
}

func scrubPubKeyFormat(pubKey []byte) ([]byte, error) {
	if len(pubKey) == 33 && pubKey[0] == 5 {
		return pubKey[1:], nil
	} else if len(pubKey) == 32 {
		return pubKey, nil
	}
	return nil, errors.New("invalid public key")
}

func createKeyPair(privKey []byte) (map[string]interface{}, error) {
	if err := validatePrivKey(privKey); err != nil {
		return nil, err
	}

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, privKey)

	for {
		pubKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

		_, err := ed25519ToX25519PublicKey(pubKey)
		if err == nil {
			formattedPubKey := make([]byte, 33)
			formattedPubKey[0] = 5
			copy(formattedPubKey[1:], pubKey)
			return map[string]interface{}{
				"pubKey":  formattedPubKey,
				"privKey": privKey,
			}, nil
		}

		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		copy(privKey, seed)
	}
}

func ed25519ToX25519PublicKey(edPubKey []byte) ([]byte, error) {
	if len(edPubKey) != 32 {
		return nil, errors.New("invalid ed25519 public key length")
	}

	p := new(big.Int).SetBytes([]byte{
		0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
	})

	yBytes := make([]byte, 32)
	copy(yBytes, edPubKey)
	for i := 0; i < 16; i++ {
		yBytes[i], yBytes[31-i] = yBytes[31-i], yBytes[i]
	}

	y := new(big.Int).SetBytes(yBytes)
	if y.Cmp(p) >= 0 {
		return nil, errors.New("invalid ed25519 public key")
	}

	one := big.NewInt(1)
	yPlus1 := new(big.Int).Add(y, one)
	yMinus1 := new(big.Int).Sub(p, y)
	yMinus1.Add(yMinus1, one)

	if yMinus1.Sign() == 0 {
		return nil, errors.New("invalid ed25519 public key")
	}

	yMinus1Inv := new(big.Int).ModInverse(yMinus1, p)
	if yMinus1Inv == nil {
		return nil, errors.New("invalid ed25519 public key")
	}

	u := new(big.Int).Mul(yPlus1, yMinus1Inv)
	u.Mod(u, p)

	uBytes := u.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(uBytes):], uBytes)

	for i := 0; i < 16; i++ {
		result[i], result[31-i] = result[31-i], result[i]
	}

	return result, nil
}

func calculateAgreement(pubKey, privKey []byte) ([]byte, error) {
	scrubbedPubKey, err := scrubPubKeyFormat(pubKey)
	if err != nil {
		return nil, err
	}
	if err := validatePrivKey(privKey); err != nil {
		return nil, err
	}

	h := sha512.Sum512(privKey)
	var scalar [32]byte
	copy(scalar[:], h[:32])

	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	x25519PubKey, err := ed25519ToX25519PublicKey(scrubbedPubKey)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(scalar[:], x25519PubKey)
	if err != nil {
		return nil, err
	}
	return shared, nil
}

func calculateSignature(privKey, message []byte) ([]byte, error) {
	if err := validatePrivKey(privKey); err != nil {
		return nil, err
	}
	if len(message) == 0 {
		return nil, errors.New("invalid message")
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, privKey)
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

func verifySignature(pubKey, message, signature []byte, isInit bool) (bool, error) {
	scrubbedPubKey, err := scrubPubKeyFormat(pubKey)
	if err != nil {
		return false, err
	}
	if len(message) == 0 {
		return false, errors.New("invalid message")
	}
	if len(signature) != 64 {
		return false, errors.New("invalid signature")
	}
	if isInit {
		return true, nil
	}
	publicKey := ed25519.PublicKey(scrubbedPubKey)
	return ed25519.Verify(publicKey, message, signature), nil
}

func generateKeyPair() (map[string]interface{}, error) {
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		return nil, err
	}
	return createKeyPair(privKey)
}

func jsCreateKeyPair(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return js.ValueOf(map[string]interface{}{"error": "invalid number of arguments"})
	}
	privKey := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(privKey, args[0])
	result, err := createKeyPair(privKey)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	pubKeyJS := js.Global().Get("Uint8Array").New(len(result["pubKey"].([]byte)))
	js.CopyBytesToJS(pubKeyJS, result["pubKey"].([]byte))
	privKeyJS := js.Global().Get("Uint8Array").New(len(result["privKey"].([]byte)))
	js.CopyBytesToJS(privKeyJS, result["privKey"].([]byte))
	return js.ValueOf(map[string]interface{}{"pubKey": pubKeyJS, "privKey": privKeyJS})
}

func jsCalculateAgreement(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf(map[string]interface{}{"error": "invalid number of arguments"})
	}
	pubKey := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(pubKey, args[0])
	privKey := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(privKey, args[1])
	result, err := calculateAgreement(pubKey, privKey)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	resultJS := js.Global().Get("Uint8Array").New(len(result))
	js.CopyBytesToJS(resultJS, result)
	return resultJS
}

func jsCalculateSignature(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf(map[string]interface{}{"error": "invalid number of arguments"})
	}
	privKey := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(privKey, args[0])
	message := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(message, args[1])
	result, err := calculateSignature(privKey, message)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	resultJS := js.Global().Get("Uint8Array").New(len(result))
	js.CopyBytesToJS(resultJS, result)
	return resultJS
}

func jsVerifySignature(this js.Value, args []js.Value) interface{} {
	if len(args) != 4 {
		return js.ValueOf(map[string]interface{}{"error": "invalid number of arguments"})
	}
	pubKey := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(pubKey, args[0])
	message := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(message, args[1])
	signature := make([]byte, args[2].Get("length").Int())
	js.CopyBytesToGo(signature, args[2])
	isInit := args[3].Bool()
	result, err := verifySignature(pubKey, message, signature, isInit)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	return js.ValueOf(result)
}

func jsGenerateKeyPair(this js.Value, args []js.Value) interface{} {
	result, err := generateKeyPair()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	pubKeyJS := js.Global().Get("Uint8Array").New(len(result["pubKey"].([]byte)))
	js.CopyBytesToJS(pubKeyJS, result["pubKey"].([]byte))
	privKeyJS := js.Global().Get("Uint8Array").New(len(result["privKey"].([]byte)))
	js.CopyBytesToJS(privKeyJS, result["privKey"].([]byte))
	return js.ValueOf(map[string]interface{}{"pubKey": pubKeyJS, "privKey": privKeyJS})
}

func main() {
	c := make(chan struct{})
	js.Global().Set("goCrypto", js.ValueOf(map[string]interface{}{
		"createKeyPair":      js.FuncOf(jsCreateKeyPair),
		"calculateAgreement": js.FuncOf(jsCalculateAgreement),
		"calculateSignature": js.FuncOf(jsCalculateSignature),
		"verifySignature":    js.FuncOf(jsVerifySignature),
		"generateKeyPair":    js.FuncOf(jsGenerateKeyPair),
	}))
	<-c
}
