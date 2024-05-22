package main

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"syscall/js"
	"theraCrypto/cmd/crypto"
	"time"
)

func JsWrapper[T any](F func(args []js.Value) (T, error), name string, numArgs int) js.Func {

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

func JsWrapperCrypto(args []js.Value, action func([]byte) ([]byte, error)) (interface{}, error) {
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

// https://blog.claude.nl/posts/interface-between-go-1.16-and-javascript-syscall-js/
func main() {

	now := time.Now()

	fmt.Println("Go Web Assembly ", now)

	aesRepo := crypto.KeyRepo[crypto.AesKey]{}
	privRepo := crypto.KeyRepo[rsa.PrivateKey]{}
	pubRepo := crypto.KeyRepo[rsa.PublicKey]{}

	privRepo.Init(1)
	pubRepo.Init(4)
	aesRepo.Init(3)

	js.Global().Set("GeneratePrivKey", JsWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeNumber {
			return false, errors.New("Wrong argument passed, Expected int length of key")
		}
		length := args[0].Int()

		status, err := crypto.GeneratePrivKey(&privRepo, 0, length)

		if nil == err {
			crypto.ExtractPubKey(&privRepo.Keys[0], &pubRepo.Keys[0])
		}
		return status, err

	}, "GeneratePrivKey", 1))

	js.Global().Set("LoadPrivKey", JsWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString {
			return false, errors.New("Wrong argument passed, Expected b64 string")
		}
		input := args[0].String()
		status, err := crypto.LoadPrivKey(input, &privRepo, 0)
		if nil == err {
			crypto.ExtractPubKey(&privRepo.Keys[0], &pubRepo.Keys[0])
		}
		return status, err

	}, "LoadPrivKey", 1))

	js.Global().Set("LoadPubKey", JsWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString || args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (b64 string, keyNum int)")
		}
		b64pubKey, num := args[0].String(), args[1].Int()

		if num == 0 {
			return false, errors.New("Could not load to bank 0")
		}

		return crypto.LoadPubKey(b64pubKey, &pubRepo, num)

	}, "LoadPubKey", 2))

	js.Global().Set("Encrypt", JsWrapper(func(args []js.Value) (interface{}, error) {
		return JsWrapperCrypto(args, func(input []byte) ([]byte, error) {
			return crypto.EncryptPrivKey(&privRepo, 0, input)

		})
	}, "Encrypt", 1))

	js.Global().Set("EncryptPubKey", JsWrapper(func(args []js.Value) (interface{}, error) {

		if args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (text []byte, keyNum int)")
		}

		num := args[1].Int()

		return JsWrapperCrypto(args[:1], func(input []byte) ([]byte, error) {
			return crypto.EncryptPubKey(&pubRepo, num, input)

		})
	}, "EncryptPubKey", 2))

	js.Global().Set("Decrypt", JsWrapper(func(args []js.Value) (interface{}, error) {
		return JsWrapperCrypto(args, func(input []byte) ([]byte, error) {
			return crypto.DecryptPrivKey(&privRepo, 0, input)

		})

	}, "Decrypt", 1))

	js.Global().Set("FetchPrivKey", JsWrapper(func(args []js.Value) (string, error) {

		return crypto.FetchPrivKey(&privRepo, 0)

	}, "FetchPrivKey", 0))

	js.Global().Set("FetchPubKey", JsWrapper(func(args []js.Value) (string, error) {

		if args[0].Type() != js.TypeNumber {
			return "", errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return crypto.FetchPubKey(&pubRepo, num)

	}, "FetchPubKey", 1))

	js.Global().Set("GenerateAesKey", JsWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return crypto.GenerateAesKey(&aesRepo, num)
	}, "GenerateAesKey", 1))

	js.Global().Set("LoadAesKey", JsWrapper(func(args []js.Value) (bool, error) {

		if args[0].Type() != js.TypeString || args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (b64 string, keyNum int)")
		}
		b64Key, num := args[0].String(), args[1].Int()

		return crypto.LoadAesKey(b64Key, &aesRepo, num)

	}, "LoadAesKey", 2))

	js.Global().Set("FetchAesKey", JsWrapper(func(args []js.Value) (string, error) {

		if args[0].Type() != js.TypeNumber {
			return "", errors.New("Wrong arguments passed, Expected keyNum int")
		}
		num := args[0].Int()
		return crypto.FetchAesKey(&aesRepo, num)

	}, "FetchAesKey", 1))

	js.Global().Set("EncryptAesBlock", JsWrapper(func(args []js.Value) (interface{}, error) {

		if args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (text []byte, keyNum int)")
		}

		num := args[1].Int()

		return JsWrapperCrypto(args[:1], func(input []byte) ([]byte, error) {
			return crypto.EncryptAESBlock(&aesRepo, num, input)

		})
	}, "EncryptAesBlock", 2))

	js.Global().Set("DecryptAesBlock", JsWrapper(func(args []js.Value) (interface{}, error) {

		if args[1].Type() != js.TypeNumber {
			return false, errors.New("Wrong arguments passed, Expected (text []byte, keyNum int)")
		}

		num := args[1].Int()

		return JsWrapperCrypto(args[:1], func(input []byte) ([]byte, error) {
			return crypto.DecryptAESBlock(&aesRepo, num, input)

		})
	}, "DecryptAesBlock", 2))

	js.Global().Set("FromBase64", JsWrapper(func(args []js.Value) (interface{}, error) {

		if args[0].Type() != js.TypeString {
			return false, errors.New("Wrong arguments passed, Expected (base64 string)")
		}

		input := args[0].String()
		return base64.StdEncoding.DecodeString(input)

	}, "FromBase64", 1))

	js.Global().Set("ToBase64", JsWrapper(func(args []js.Value) (string, error) {

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
