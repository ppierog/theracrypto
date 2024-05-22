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

// https://blog.claude.nl/posts/interface-between-go-1.16-and-javascript-syscall-js/
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

type u8 interface {
	uint8
}

var privRepo KeyStorage[rsa.PrivateKey]
var pubRepo [3]KeyStorage[rsa.PublicKey]

func GenerateKey(length int) (bool, error) {
	privRepo.Loaded = false
	if length != 2048 && length != 4096 {
		return false, errors.New("Not supported key length, use 2048 or 4096")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
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

func encryptPubKey(plain []byte, key *rsa.PublicKey) ([]byte, error) {

	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, key, plain)

	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func EncryptPubKey(plain []byte, num KeyNum) ([]byte, error) {
	if num > Key3 {
		return nil, errors.New("Bank Not supported")
	}
	if !pubRepo[num].Loaded {
		return nil, errors.New("Key Not loaded")
	}
	return encryptPubKey(plain, &pubRepo[num].Key)

}

func Encrypt(plain []byte) ([]byte, error) {
	if !privRepo.Loaded {
		return nil, errors.New("PrivateKey not loaded")
	}

	return encryptPubKey(plain, &privRepo.Key.PublicKey)
}

func Decrypt(cipher []byte) ([]byte, error) {
	if !privRepo.Loaded {
		return nil, errors.New("PrivateKey not loaded")
	}

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, &privRepo.Key, cipher)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func JsonWrapper[T any](F func(args []js.Value) (T, error), name string) js.Func {

	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {

		status, err := F(args)

		if err != nil {
			fmt.Printf("Unable to execute %s : err %v\n", name, err)
			return err.Error()

		}

		return status
	})

	return jsonFunc

}

func JsonWrapperCryptoRSA(args []js.Value, action func([]byte) ([]byte, error)) (interface{}, error) {
	if len(args) != 1 {
		return nil, errors.New("Invalid number of arguments passed")
	}

	if args[0].Type() != js.TypeObject || args[0].Length() == 0 {
		return nil, errors.New("Wrong argument passed, Expected array with non zero length")
	}
	//@TODO:  Copy overhead
	var in []uint8
	for i := 0; i < args[0].Length(); i++ {
		in = append(in, (uint8(args[0].Index(i).Int())))
	}

	encrypted, err := action(in)
	if err != nil {
		return nil, err
	}
	//@TODO:  Copy overhead
	var ret []interface{}
	for i := 0; i < len(encrypted); i++ {
		ret = append(ret, encrypted[i])
	}

	return ret, nil

}

func main() {

	now := time.Now()
	fmt.Println("Go Web Assembly ", now)

	js.Global().Set("GenerateKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 1 {
			return false, errors.New("Invalid number of arguments passed")
		}
		length := args[0].Int()

		return GenerateKey(length)

	}, "GenerateKey"))

	js.Global().Set("LoadKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 1 {
			return false, errors.New("Invalid number of arguments passed")
		}
		input := args[0].String()
		return LoadPrivKey(input)

	}, "LoadKey"))

	js.Global().Set("LoadPubKey", JsonWrapper(func(args []js.Value) (bool, error) {
		if len(args) != 2 {
			return false, errors.New("Invalid number of arguments passed")
		}
		pubKey := args[0].String()
		num := args[1].Int()
		return LoadPubKey(pubKey, KeyNum(num))

	}, "LoadPubKey"))

	/*
		myTab = "aslk1234567890"
		let utf8Encode = new TextEncoder();
		let encoded = utf8Encode.encode(myTab);

		retTab = Encrypt(encoded)
		//GenerateKey(2048)
		myTab = "aslk1234567890"
		//let utf8Encode = new TextEncoder();
		//let encoded = utf8Encode.encode(myTab);

		encrypted = Encrypt(encoded)
		decrypted = Decrypt(encrypted)
		console.log(decrypted)
		String.fromCharCode.apply(null,decrypted)
	*/
	js.Global().Set("Encrypt", JsonWrapper(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("Invalid number of arguments passed")
		}

		if args[0].Type() != js.TypeObject || args[0].Length() == 0 {
			return nil, errors.New("Wrong argument passed, Expected array with non zero length")
		}
		//@TODO:  Copy overhead
		var in []uint8
		for i := 0; i < args[0].Length(); i++ {
			in = append(in, (uint8(args[0].Index(i).Int())))
		}

		encrypted, err := Encrypt(in)
		if err != nil {
			return nil, err
		}
		//@TODO:  Copy overhead
		var ret []interface{}
		for i := 0; i < len(encrypted); i++ {
			ret = append(ret, encrypted[i])
		}

		return ret, nil

	}, "Encrypt"))

	js.Global().Set("Decrypt", JsonWrapper(func(args []js.Value) (interface{}, error) {
		if len(args) != 1 {
			return "", errors.New("Invalid number of arguments passed")
		}
		var in []uint8
		for i := 0; i < args[0].Length(); i++ {
			in = append(in, (uint8(args[0].Index(i).Int())))
		}
		decrypted, err := Decrypt(in)
		if err != nil {
			return nil, err
		}
		var ret []interface{}
		for i := 0; i < len(decrypted); i++ {
			ret = append(ret, decrypted[i])
		}
		return ret, nil

	}, "Decrypt"))

	js.Global().Set("FetchPrivKey", JsonWrapper(func(args []js.Value) (string, error) {
		if len(args) != 0 {
			return "", errors.New("Invalid number of arguments passed")
		}
		return FetchPrivKey()

	}, "FetchPrivKey"))

	<-make(chan int64)
}
