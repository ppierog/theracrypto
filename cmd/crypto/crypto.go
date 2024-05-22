package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
)

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

type CryptoFunction[T Key] func(Key *T, in []byte) ([]byte, error)
type GeneratorFunction[T Key] func() (T, []byte, error)

func ExtractPubKey(from *KeyStorage[rsa.PrivateKey], to *KeyStorage[rsa.PublicKey]) {
	to.Key = from.Key.PublicKey
	marshaled := x509.MarshalPKCS1PublicKey(&to.Key)
	to.MarshaledB64 = base64.StdEncoding.EncodeToString(marshaled)
	to.Loaded = true
}

func GenerateKey[T Key](repo *KeyRepo[T], num int, generator GeneratorFunction[T]) (bool, error) {
	if num >= len(repo.Keys) {
		return false, errors.New("bank not supported")
	}
	repo.Keys[num].Loaded = false
	key, marshaled, error := generator()
	if error != nil {
		return false, errors.New("could not generate key")
	}

	repo.Keys[num].Key = key
	repo.Keys[num].Loaded = true
	repo.Keys[num].MarshaledB64 = base64.StdEncoding.EncodeToString(marshaled)
	return true, nil
}

func LoadKey[T Key](b64 string, repo *KeyRepo[T], num int, parser func([]byte) (*T, error)) (bool, error) {
	if num >= len(repo.Keys) {
		return false, errors.New("bank not supported")
	}

	repo.Keys[num].Loaded = false
	marshaled, err := base64.StdEncoding.DecodeString(b64)

	if err != nil {
		return false, err
	}
	key, err := parser(marshaled)

	if err != nil {
		return false, err
	}
	repo.Keys[num].Key = *key
	repo.Keys[num].Loaded = true
	repo.Keys[num].MarshaledB64 = b64
	return true, nil

}

func FetchKey[T Key](repo *KeyRepo[T], num int) (string, error) {
	if num >= len(repo.Keys) {
		return "", errors.New("bank not supported")
	}
	if !repo.Keys[num].Loaded {
		return "", errors.New("key not loaded")
	}

	return repo.Keys[num].MarshaledB64, nil
}

func Crypto[T Key](repo *KeyRepo[T], num int, in []byte, crypto CryptoFunction[T]) ([]byte, error) {
	if num >= len(repo.Keys) {
		return nil, errors.New("bank not supported")
	}
	if !repo.Keys[num].Loaded {
		return nil, errors.New("key not loaded")
	}
	return crypto(&repo.Keys[num].Key, in)

}

func GeneratePrivKey(repo *KeyRepo[rsa.PrivateKey], num int, length int) (bool, error) {
	if length != 2048 && length != 4096 {
		return false, errors.New("wrong key length, supported sizes : 2048 or 4096")
	}
	return GenerateKey(repo, num, func() (rsa.PrivateKey, []byte, error) {
		privateKey, err := rsa.GenerateKey(rand.Reader, length)
		if err != nil {
			return rsa.PrivateKey{}, nil, err
		}
		return *privateKey, x509.MarshalPKCS1PrivateKey(privateKey), nil
	})
}

func GenerateAesKey(repo *KeyRepo[AesKey], num int) (bool, error) {
	return GenerateKey(repo, num, func() (AesKey, []byte, error) {
		key := make([]byte, AES_LEN)
		n, err := rand.Read(key)
		if err != nil || n != AES_LEN {
			return AesKey{}, nil, err
		}
		return AesKey(key), key, nil
	})
}

func LoadPrivKey(b64Priv string, repo *KeyRepo[rsa.PrivateKey], num int) (bool, error) {
	return LoadKey(b64Priv, repo, num, x509.ParsePKCS1PrivateKey)
}

func FetchPrivKey(repo *KeyRepo[rsa.PrivateKey], num int) (string, error) {
	return FetchKey(repo, num)
}

func LoadPubKey(b64Priv string, repo *KeyRepo[rsa.PublicKey], num int) (bool, error) {
	return LoadKey(b64Priv, repo, num, x509.ParsePKCS1PublicKey)
}

func FetchPubKey(repo *KeyRepo[rsa.PublicKey], num int) (string, error) {
	return FetchKey(repo, num)
}

func LoadAesKey(b64Key string, repo *KeyRepo[AesKey], num int) (bool, error) {

	return LoadKey(b64Key, repo, num, func(b []byte) (*AesKey, error) {
		aesKey := new(AesKey)
		*aesKey = AesKey(b)
		return aesKey, nil
	})
}

func FetchAesKey(repo *KeyRepo[AesKey], num int) (string, error) {
	return FetchKey(repo, num)
}

func EncryptPubKey(repo *KeyRepo[rsa.PublicKey], num int, in []byte) ([]byte, error) {

	return Crypto(repo, num, in, func(key *rsa.PublicKey, in []byte) ([]byte, error) {
		return rsa.EncryptPKCS1v15(rand.Reader, key, in)
	})

}

func EncryptPrivKey(repo *KeyRepo[rsa.PrivateKey], num int, in []byte) ([]byte, error) {

	return Crypto(repo, num, in, func(key *rsa.PrivateKey, in []byte) ([]byte, error) {
		return rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, in)
	})

}

func DecryptPrivKey(repo *KeyRepo[rsa.PrivateKey], num int, in []byte) ([]byte, error) {

	return Crypto(repo, num, in, func(key *rsa.PrivateKey, in []byte) ([]byte, error) {
		return rsa.DecryptPKCS1v15(rand.Reader, key, in)
	})

}

func EncryptAESBlock(repo *KeyRepo[AesKey], num int, in []byte) ([]byte, error) {
	return Crypto(repo, num, in, func(key *AesKey, in []byte) ([]byte, error) {

		c, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, errors.New("could not create new cipher")
		}

		var out [16]byte

		c.Encrypt(out[:], in)
		return out[:], nil
	})

}

func EncryptAES(repo *KeyRepo[AesKey], num int, in []byte) ([]byte, error) {
	return Crypto(repo, num, in, func(key *AesKey, in []byte) ([]byte, error) {

		c, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, errors.New("could not create new cipher")
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		ciphertext := make([]byte, aes.BlockSize+len(in))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, errors.New("could not generate iv")
		}

		stream := cipher.NewCFBEncrypter(c, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], in)

		return ciphertext, nil
	})

}

func DecryptAESBlock(repo *KeyRepo[AesKey], num int, in []byte) ([]byte, error) {
	return Crypto(repo, num, in, func(key *AesKey, in []byte) ([]byte, error) {

		c, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, errors.New("could not create new cipher")
		}

		var out [16]byte
		c.Decrypt(out[:], in)

		return out[:], nil
	})

}

func DecryptAES(repo *KeyRepo[AesKey], num int, in []byte) ([]byte, error) {
	return Crypto(repo, num, in, func(key *AesKey, in []byte) ([]byte, error) {

		c, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, errors.New("could not create new cipher")
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		if len(in) < aes.BlockSize {
			return nil, errors.New("ciphertext to short")
		}
		iv := in[:aes.BlockSize]
		in = in[aes.BlockSize:]

		stream := cipher.NewCFBDecrypter(c, iv)

		// XORKeyStream can work in-place if the two arguments are the same.
		stream.XORKeyStream(in, in)
		return in, nil

	})

}
