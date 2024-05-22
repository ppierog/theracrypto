package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"syscall/js"
)

type PKeyRepo struct {
	Key    rsa.PrivateKey
	Loaded bool
}

var pkeyRepo PKeyRepo

func GenerateKey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	marshaledPriv := x509.MarshalPKCS1PrivateKey(privateKey)
	b64Priv := base64.StdEncoding.EncodeToString(marshaledPriv)
	return b64Priv, nil

}

func LoadKey(b64Priv string) (bool, error) {
	marshaledPriv, err := base64.StdEncoding.DecodeString(b64Priv)

	if err != nil {
		return false, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(marshaledPriv)

	if err != nil {
		return false, err
	}
	pkeyRepo.Key = *privateKey
	pkeyRepo.Loaded = true
	return true, nil
}

func EncryptPubKey(plainText string) (string, error) {
	if !pkeyRepo.Loaded {
		return "", errors.New("PrivateKey not loaded")
	}
	msg := []byte(plainText)
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, &pkeyRepo.Key.PublicKey, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}

func DecryptPrivKey(b64cipher string) (string, error) {
	if !pkeyRepo.Loaded {
		return "", errors.New("PrivateKey not loaded")
	}
	cipher, err := base64.StdEncoding.DecodeString(b64cipher)

	if err != nil {
		return "", err
	}
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, &pkeyRepo.Key, cipher)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func JsonWrapper[T any](F func(args []js.Value) (T, error)) js.Func {

	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {

		status, err := F(args)

		if err != nil {
			fmt.Printf("Unable to execute %s : err %s\n", F, err)
			return err.Error()

		}

		return status
	})

	return jsonFunc

}

func main() {

	now := time.Now()
	fmt.Println("Go Web Assembly %s", now)

	js.Global().Set("GenerateKey", JsonWrapper(func(args []js.Value) (string, error) {
		if len(args) != 0 {
			return "", errors.New("Invalid no of arguments passed")
		}
		return GenerateKey()

	}))

	js.Global().Set("LoadKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 1 {
			return false, errors.New("Invalid no of arguments passed")
		}
		input := args[0].String()
		return LoadKey(input)

	}))

	<-make(chan int64)
}
