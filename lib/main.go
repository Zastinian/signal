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
	jsPromise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			seed, err := copyBytesFromJS(args[0])
			if err != nil || len(seed) != 32 {
				reject.Invoke(js.Global().Get("Error").New("Invalid private key seed"))
				return
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

			privKeyJS := js.Global().Get("Uint8Array").New(len(privateKey))
			js.CopyBytesToJS(privKeyJS, privateKey)
			response.Set("privKey", privKeyJS)

			resolve.Invoke(response)
		}()
		return nil
	}))
	return jsPromise
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	jsPromise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				reject.Invoke(js.Global().Get("Error").New("Failed to generate random bytes"))
				return
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

			privKeyJS := js.Global().Get("Uint8Array").New(len(privateKey))
			js.CopyBytesToJS(privKeyJS, privateKey)
			response.Set("privKey", privKeyJS)

			resolve.Invoke(response)
		}()
		return nil
	}))
	return jsPromise
}

func calculateAgreement(this js.Value, args []js.Value) interface{} {
	jsPromise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			pubKey, err := copyBytesFromJS(args[0])
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("Invalid public key"))
				return
			}
			privKeySeed, err := copyBytesFromJS(args[1])
			if err != nil || len(privKeySeed) != 32 {
				reject.Invoke(js.Global().Get("Error").New("Invalid private key"))
				return
			}

			var theirPublicKey, scrubbedPubKey [32]byte
			if len(pubKey) == 33 && pubKey[0] == 5 {
				copy(scrubbedPubKey[:], pubKey[1:])
			} else if len(pubKey) == 32 {
				copy(scrubbedPubKey[:], pubKey)
			} else {
				reject.Invoke(js.Global().Get("Error").New("Invalid public key format"))
				return
			}
			copy(theirPublicKey[:], scrubbedPubKey[:])

			var myPrivateKey [32]byte
			copy(myPrivateKey[:], privKeySeed)

			sharedSecret, err := curve25519.X25519(myPrivateKey[:], theirPublicKey[:])
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("Failed to calculate agreement"))
				return
			}

			result := js.Global().Get("Uint8Array").New(len(sharedSecret))
			js.CopyBytesToJS(result, sharedSecret)
			resolve.Invoke(result)
		}()
		return nil
	}))
	return jsPromise
}

func calculateSignature(this js.Value, args []js.Value) interface{} {
	jsPromise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			privKeySeed, err := copyBytesFromJS(args[0])
			if err != nil || len(privKeySeed) != 32 {
				reject.Invoke(js.Global().Get("Error").New("Invalid private key"))
				return
			}
			message, err := copyBytesFromJS(args[1])
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("Invalid message"))
				return
			}

			privateKey := ed25519.NewKeyFromSeed(privKeySeed)
			signature := ed25519.Sign(privateKey, message)

			result := js.Global().Get("Uint8Array").New(len(signature))
			js.CopyBytesToJS(result, signature)
			resolve.Invoke(result)
		}()
		return nil
	}))
	return jsPromise
}

func verifySignature(this js.Value, args []js.Value) interface{} {
	jsPromise := js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			if args[3].Bool() {
				resolve.Invoke(true)
				return
			}

			pubKey, err := copyBytesFromJS(args[0])
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("Invalid public key"))
				return
			}
			msg, err := copyBytesFromJS(args[1])
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("Invalid message"))
				return
			}
			sig, err := copyBytesFromJS(args[2])
			if err != nil || len(sig) != 64 {
				reject.Invoke(js.Global().Get("Error").New("Invalid signature"))
				return
			}

			var scrubbedPubKey [32]byte
			if len(pubKey) == 33 && pubKey[0] == 5 {
				copy(scrubbedPubKey[:], pubKey[1:])
			} else if len(pubKey) == 32 {
				copy(scrubbedPubKey[:], pubKey)
			} else {
				reject.Invoke(js.Global().Get("Error").New("Invalid public key format"))
				return
			}

			isValid := ed25519.Verify(ed25519.PublicKey(scrubbedPubKey[:]), msg, sig)
			resolve.Invoke(isValid)
		}()
		return nil
	}))
	return jsPromise
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
