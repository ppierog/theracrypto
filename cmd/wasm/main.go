package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"syscall/js"
	"time"
)

// https://blog.claude.nl/posts/interface-between-go-1.16-and-javascript-syscall-js/

const AES_LEN = 32

type AesKey [AES_LEN]byte

type Key interface {
	rsa.PrivateKey | rsa.PublicKey | AesKey
}

type KeyStorage[T Key] struct {
	Key          T
	Loaded       bool
	MarshaledB64 string
}

type KeyRepo[T Key] struct {
	Keys []KeyStorage[T]
}

func (repo *KeyRepo[T]) Init(size uint32) {
	repo.Keys = make([]KeyStorage[T], size)
}

var privRepo KeyRepo[rsa.PrivateKey]
var pubRepo KeyRepo[rsa.PublicKey]
var aesRepo KeyRepo[AesKey]

func extractPubKey() {
	pubRepo.Keys[0].Key = privRepo.Keys[0].Key.PublicKey
	marshaled := x509.MarshalPKCS1PublicKey(&pubRepo.Keys[0].Key)
	pubRepo.Keys[0].MarshaledB64 = base64.StdEncoding.EncodeToString(marshaled)
	pubRepo.Keys[0].Loaded = true
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

func encryptPubKey(plain []byte, key *rsa.PublicKey) ([]byte, error) {

	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, key, plain)

	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func GenerateKey[T Key](repo *KeyRepo[T], num int, generator func() (T, []byte, error)) (bool, error) {
	if num > len(repo.Keys) || num < 0 {
		return false, errors.New("Bank Not supported")
	}
	repo.Keys[num].Loaded = false
	key, marshaled, error := generator()
	if error != nil {
		return false, errors.New("Could not generate key")
	}

	repo.Keys[num].Key = key
	repo.Keys[num].Loaded = true
	repo.Keys[num].MarshaledB64 = base64.StdEncoding.EncodeToString(marshaled)
	return true, nil
}

func LoadKey[T Key](b64 string, repo *KeyRepo[T], num int, parser func([]byte) (*T, error)) (bool, error) {
	if num > len(repo.Keys) || num < 0 {
		return false, errors.New("Bank Not supported")
	}
	return loadKey(b64, &repo.Keys[num], parser)
}

func FetchKey[T Key](repo *KeyRepo[T], num int) (string, error) {
	if num > len(repo.Keys) || num < 0 {
		return "", errors.New("Bank Not supported")
	}
	if !repo.Keys[num].Loaded {
		return "", errors.New("Key not loaded")
	}

	return repo.Keys[num].MarshaledB64, nil
}

func LoadPrivKey(b64Priv string) (bool, error) {
	status, err := loadKey(b64Priv, &privRepo.Keys[0], x509.ParsePKCS1PrivateKey)
	if nil != err {
		return false, err
	}

	extractPubKey()

	return status, nil

}

func FetchPrivKey() (string, error) {
	return FetchKey(&privRepo, 0)
}

func EncryptPubKey(plain []byte, num int) ([]byte, error) {
	if num > len(pubRepo.Keys) {
		return nil, errors.New("Bank Not supported")
	}
	if !pubRepo.Keys[num].Loaded {
		return nil, errors.New("Key Not loaded")
	}
	return encryptPubKey(plain, &pubRepo.Keys[num].Key)

}

func CryptoAES(plain []byte, num int) ([]byte, error) {
	if num > len(aesRepo.Keys) {
		return nil, errors.New("Bank Not supported")
	}
	if !aesRepo.Keys[num].Loaded {
		return nil, errors.New("Key Not loaded")
	}
	c, err := aes.NewCipher(aesRepo.Keys[num].Key[:])
	if err != nil {
		return nil, errors.New("Could not create new cipher")
	}

	out := make([]byte, len(plain))

	c.Encrypt(out, []byte(plain))
	return out, nil
}

func Encrypt(plain []byte) ([]byte, error) {
	if !privRepo.Keys[0].Loaded {
		return nil, errors.New("PrivateKey not loaded")
	}

	return encryptPubKey(plain, &privRepo.Keys[0].Key.PublicKey)
}

func Decrypt(cipher []byte) ([]byte, error) {
	if !privRepo.Keys[0].Loaded {
		return nil, errors.New("PrivateKey not loaded")
	}

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, &privRepo.Keys[0].Key, cipher)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func JsonWrapper[T any](F func(args []js.Value) (T, error), name string, numArgs int) js.Func {

	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {

		if len(args) != numArgs {
			err := errors.New("Invalid number of arguments passed " +
				strconv.Itoa(len(args)) + ", expected " + strconv.Itoa(numArgs))
			return map[string]interface{}{
				"error": err.Error(),
			}

		}
		status, err := F(args)

		if err != nil {
			fmt.Printf("Unable to execute %s : err %v\n", name, err)
			return map[string]interface{}{
				"error": err.Error(),
			}

		}

		return map[string]interface{}{
			"ret": status,
		}
	})

	return jsonFunc

}

func JsonWrapperCrypto(args []js.Value, action func([]byte) ([]byte, error)) (interface{}, error) {
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

	privRepo.Init(1)
	pubRepo.Init(4)
	aesRepo.Init(3)

	fmt.Println("Go Web Assembly ", now)

	js.Global().Set("GeneratePrivKey", JsonWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeNumber {
			return false, errors.New("Wrong argument passed, Expected int length of key")
		}
		length := args[0].Int()
		if length != 2048 && length != 4096 {
			return false, errors.New("Not supported key length, use 2048 or 4096")
		}

		return GenerateKey(&privRepo, 0, func() (rsa.PrivateKey, []byte, error) {
			privateKey, err := rsa.GenerateKey(rand.Reader, length)
			if err != nil {
				return rsa.PrivateKey{}, nil, err
			}
			return *privateKey, x509.MarshalPKCS1PrivateKey(privateKey), nil
		})

	}, "GeneratePrivKey", 1))

	js.Global().Set("LoadPrivKey", JsonWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString {
			return false, errors.New("Wrong argument passed, Expected b64 string")
		}
		input := args[0].String()
		return LoadPrivKey(input)

	}, "LoadPrivKey", 1))

	js.Global().Set("LoadPubKey", JsonWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString || args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (b64 string, keyNum int)")
		}
		b64pubKey := args[0].String()
		num := args[1].Int()
		if num == 0 {
			return false, errors.New("Could not load to bank 0")
		}

		return LoadKey(b64pubKey, &pubRepo, num, func(b []byte) (*rsa.PublicKey, error) {
			return x509.ParsePKCS1PublicKey(b)
		})

	}, "LoadPubKey", 2))

	js.Global().Set("Encrypt", JsonWrapper(func(args []js.Value) (interface{}, error) {
		return JsonWrapperCrypto(args, Encrypt)
	}, "Encrypt", 1))

	js.Global().Set("EncryptPubKey", JsonWrapper(func(args []js.Value) (interface{}, error) {

		if args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (text []byte, keyNum int)")
		}

		num := args[1].Int()

		return JsonWrapperCrypto(args[:1], func(input []byte) ([]byte, error) {
			return EncryptPubKey(input, num)

		})
	}, "EncryptPubKey", 2))

	js.Global().Set("Decrypt", JsonWrapper(func(args []js.Value) (interface{}, error) {
		return JsonWrapperCrypto(args, Decrypt)

	}, "Decrypt", 1))

	js.Global().Set("FetchPrivKey", JsonWrapper(func(args []js.Value) (string, error) {

		return FetchPrivKey()

	}, "FetchPrivKey", 0))

	js.Global().Set("FetchPubKey", JsonWrapper(func(args []js.Value) (string, error) {

		if args[0].Type() != js.TypeNumber {
			return "", errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return FetchKey(&pubRepo, num)

	}, "FetchPubKey", 1))

	js.Global().Set("GenerateAesKey", JsonWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return GenerateKey(&aesRepo, num, func() (AesKey, []byte, error) {
			key := make([]byte, AES_LEN)
			n, err := rand.Read(key)
			if err != nil || n != AES_LEN {
				return AesKey{}, nil, err
			}
			return AesKey(key), key, nil
		})

	}, "GenerateAesKey", 1))

	js.Global().Set("LoadAesKey", JsonWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString || args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (b64 string, keyNum int)")
		}
		b64Key := args[0].String()
		num := args[1].Int()

		return LoadKey(b64Key, &aesRepo, num, func(b []byte) (*AesKey, error) {
			aesKey := new(AesKey)
			*aesKey = AesKey(b)
			return aesKey, nil
		})

	}, "LoadAesKey", 2))

	js.Global().Set("FetchAesKey", JsonWrapper(func(args []js.Value) (string, error) {

		if args[0].Type() != js.TypeNumber {
			return "", errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return FetchKey(&aesRepo, num)

	}, "FetchAesKey", 1))

	js.Global().Set("CryptoAes", JsonWrapper(func(args []js.Value) (interface{}, error) {
		if args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (text []byte, keyNum int)")
		}

		num := args[1].Int()

		return JsonWrapperCrypto(args[:1], func(input []byte) ([]byte, error) {
			return CryptoAES(input, num)

		})
	}, "CryptoAes", 2))

	js.Global().Set("FromBase64", JsonWrapper(func(args []js.Value) (interface{}, error) {

		if args[0].Type() != js.TypeString {
			return false, errors.New("Wrong arguments passed, Expected (base64 string)")
		}

		input := args[0].String()
		marshaled, err := base64.StdEncoding.DecodeString(input)

		if err != nil {
			return nil, err
		}

		return marshaled, nil

	}, "FromBase64", 1))

	js.Global().Set("ToBase64", JsonWrapper(func(args []js.Value) (string, error) {

		if args[0].Type() != js.TypeObject || args[0].Length() == 0 {
			return "", errors.New("Wrong argument passed, Expected array with non zero length")
		}
		//@TODO:  Copy overhead
		var in []uint8
		for i := 0; i < args[0].Length(); i++ {
			in = append(in, (uint8(args[0].Index(i).Int())))
		}

		return base64.StdEncoding.EncodeToString(in), nil

	}, "FromBase64", 1))
	<-make(chan int64)
}
