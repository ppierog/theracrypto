package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"syscall/js"
	"time"
)

type Key interface {
	rsa.PrivateKey | rsa.PublicKey
}

type KeyStorage[T Key] struct {
	Key          T
	Loaded       bool
	MarshaledB64 string
}

type KeyNum int

const ( // iota is reset to 0
	Key1 KeyNum = iota // 0
	Key2        = iota // 1
	Key3        = iota // 2
)

var privRepo KeyStorage[rsa.PrivateKey]
var pubRepo [3]KeyStorage[rsa.PublicKey]

func GenerateKey() (bool, error) {
	privRepo.Loaded = false
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, err
	}
	privRepo.Key = *privateKey
	marshaledPriv := x509.MarshalPKCS1PrivateKey(&privRepo.Key)
	privRepo.MarshaledB64 = base64.StdEncoding.EncodeToString(marshaledPriv)
	privRepo.Loaded = true

	return true, nil
}

func fetchKey[T Key](repo *KeyStorage[T]) (string, error) {
	if !repo.Loaded {
		return "", errors.New("Key not loaded")
	}

	return repo.MarshaledB64, nil
}

func loadKey[T Key](b64key string, storage *KeyStorage[T], parser func([]byte) (*T, error)) (bool, error) {
	storage.Loaded = false
	marshaled, err := base64.StdEncoding.DecodeString(b64key)

	if err != nil {
		return false, err
	}
	key, err := parser(marshaled)

	if err != nil {
		return false, err
	}
	storage.Key = *key
	storage.Loaded = true
	storage.MarshaledB64 = b64key
	return true, nil
}

func LoadPrivKey(b64Priv string) (bool, error) {
	return loadKey(b64Priv, &privRepo, x509.ParsePKCS1PrivateKey)
}

func FetchPrivKey() (string, error) {
	return fetchKey(&privRepo)
}

func LoadPubKey(b64Pub string, num KeyNum) (bool, error) {
	if num > Key3 {
		return false, errors.New("Bank Not supported")
	}
	return loadKey(b64Pub, &pubRepo[num], x509.ParsePKCS1PublicKey)
}

func encryptPubKey(plainText string, key *rsa.PublicKey) (string, error) {

	fmt.Println("Before conversion", plainText)
	msg := []byte(plainText)
	fmt.Println("After conversion", msg)
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, key, msg)
	if err != nil {
		return "", err
	}
	fmt.Println("After encryption", cipher)
	return base64.StdEncoding.EncodeToString(cipher), nil
}

func EncryptPubKey(plainText string, num KeyNum) (string, error) {
	if num > Key3 {
		return "", errors.New("Bank Not supported")
	}
	if !pubRepo[num].Loaded {
		return "", errors.New("Key Not loaded")
	}
	return encryptPubKey(plainText, &pubRepo[num].Key)

}

func Encrypt(plainText string) (string, error) {
	if !privRepo.Loaded {
		return "", errors.New("PrivateKey not loaded")
	}
	fmt.Println("plain Text  is ", plainText)
	return encryptPubKey(plainText, &privRepo.Key.PublicKey)
}

func Decrypt(b64 string) (string, error) {
	if !privRepo.Loaded {
		return "", errors.New("PrivateKey not loaded")
	}
	cipher, err := base64.StdEncoding.DecodeString(b64)

	if err != nil {
		return "", err
	}

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, &privRepo.Key, cipher)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func ToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromBase64(b64 string) ([]byte, error) {
	cipher, err := base64.StdEncoding.DecodeString(b64)

	if err != nil {
		return nil, err
	}
	return cipher, nil
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
	fmt.Println("Go Web Assembly ", now)

	js.Global().Set("GenerateKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 0 {
			return false, errors.New("Invalid number of arguments passed")
		}
		return GenerateKey()

	}))

	js.Global().Set("LoadKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 1 {
			return false, errors.New("Invalid number of arguments passed")
		}
		input := args[0].String()
		return LoadPrivKey(input)

	}))

	js.Global().Set("LoadPubKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 2 {
			return false, errors.New("Invalid number of arguments passed")
		}
		pubKey := args[0].String()
		num := args[1].Int()
		return LoadPubKey(pubKey, KeyNum(num))

	}))

	js.Global().Set("Encrypt", JsonWrapper(func(args []js.Value) (string, error) {
		if len(args) != 1 {
			return "", errors.New("Invalid number of arguments passed")
		}
		fmt.Println("Arg0 is", args[0])
		input := args[0].String()
		fmt.Println("Arg0 is now", input)

		return Encrypt(input)

	}))

	js.Global().Set("Decrypt", JsonWrapper(func(args []js.Value) (string, error) {
		if len(args) != 1 {
			return "", errors.New("Invalid number of arguments passed")
		}
		input := args[0].String()
		return Decrypt(input)

	}))

	js.Global().Set("FetchPrivKey", JsonWrapper(func(args []js.Value) (string, error) {
		if len(args) != 0 {
			return "", errors.New("Invalid number of arguments passed")
		}
		return FetchPrivKey()

	}))

	<-make(chan int64)
}
