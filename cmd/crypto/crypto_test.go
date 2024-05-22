package crypto

import (
	"crypto/rsa"
	"errors"
	"testing"
)

type KeyGenerator[T Key] func(r *KeyRepo[T], num int) (bool, error)

type KeyLoader[T Key] func(b64 string, r *KeyRepo[T], num int) (bool, error)

func TestMain(m *testing.M) {

	m.Run()

}

func testBlankRrepo[T Key](t *testing.T, r *KeyRepo[T], generator KeyGenerator[T], loader KeyLoader[T]) {
	if len(r.Keys) != 0 {
		t.Fatalf("Wrong  state of repo after initialization")
	}
	status, err := generator(r, 0)
	if status || nil == err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from GenerateKey")
	}
	status, err = loader("", r, 0)
	if status || nil == err {
		t.Fatalf("Wrong status from LoadKey")
	}

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from GenerateKey")
	}

}

func TestBlankRepo(t *testing.T) {

	privateRepo := KeyRepo[rsa.PrivateKey]{}
	testBlankRrepo(t, &privateRepo,
		func(r *KeyRepo[rsa.PrivateKey], num int) (bool, error) {
			return GeneratePrivKey(r, 0, 2048)
		},
		func(b64 string, r *KeyRepo[rsa.PrivateKey], num int) (bool, error) {
			return LoadPrivKey(b64, r, 0)
		},
	)

	aesRepo := KeyRepo[AesKey]{}
	testBlankRrepo(t, &aesRepo,
		func(r *KeyRepo[AesKey], num int) (bool, error) {
			return GenerateAesKey(r, 0)
		},
		func(b64 string, r *KeyRepo[AesKey], num int) (bool, error) {
			return LoadAesKey(b64, r, 0)
		},
	)

	pubRepo := KeyRepo[rsa.PublicKey]{}
	testBlankRrepo(t, &pubRepo,
		func(r *KeyRepo[rsa.PublicKey], num int) (bool, error) {
			return false, errors.New("bank not supported")
		},
		func(b64 string, r *KeyRepo[rsa.PublicKey], num int) (bool, error) {
			return LoadPubKey(b64, r, 0)
		},
	)

}

func TestPrivRepo(t *testing.T) {

	privateRepo := KeyRepo[rsa.PrivateKey]{}
	publicRepo := KeyRepo[rsa.PublicKey]{}
	privateRepo.Init(1)
	publicRepo.Init(1)
	if len(privateRepo.Keys) != 1 || len(publicRepo.Keys) != 1 {
		t.Fatalf("Wrong  state of repo after initialization")
	}
	status, err := GeneratePrivKey(&privateRepo, 1, 2048)

	if status || nil == err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from GenerateKey")
	}

	status, err = GeneratePrivKey(&privateRepo, 0, 2048)

	if !status || nil != err {
		t.Fatalf("Wrong status from GenerateKey")
	}
	_, err = FetchPrivKey(&privateRepo, 1)

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from FetchPrivKey")
	}
	b64Key1, err := FetchPrivKey(&privateRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchPrivKey")
	}

	t.Log(b64Key1)
	_, err = LoadPrivKey(b64Key1, &privateRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from LoadPrivKey")
	}
	b64Key2, err := FetchPrivKey(&privateRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchPrivKey")
	}

	if b64Key1 != b64Key2 {
		t.Fatalf("Priv Key Inconsistency")
	}

	in := "aslk1234"

	cipher, err := EncryptPrivKey(&privateRepo, 0, []byte(in))
	t.Log(in)
	t.Log([]byte(in))

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptPrivKey")
	}
	out, err := DecryptPrivKey(&privateRepo, 0, []byte(cipher))

	if err != nil {
		t.Fatalf("Wrong status from DecryptPrivKey")
	}
	t.Log(out)
	t.Log(string(out))
	if string(out) != in {
		t.Fatalf("Wrong Encrypt/Decrypt")
	}
	_, err = FetchPubKey(&publicRepo, 0)

	if err == nil || err.Error() != "key not loaded" {
		t.Fatalf("Wrong status from FetchPubKey")
	}

	ExtractPubKey(&privateRepo.Keys[0], &publicRepo.Keys[0])
	b64PubKey1, err := FetchPubKey(&publicRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchPubKey")
	}
	status, err = LoadPubKey(b64PubKey1, &publicRepo, 0)
	if !status || nil != err {
		t.Fatalf("Wrong status from LoadPubKey")
	}

	b64PubKey2, err := FetchPubKey(&publicRepo, 0)

	if b64PubKey1 != b64PubKey2 {
		t.Fatalf("Pub Key Inconsistency")
	}

	in = "aslk123456789"
	cipher, err = EncryptPubKey(&publicRepo, 0, []byte(in))
	t.Log(in)
	t.Log([]byte(in))

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptPubKey")
	}
	out, err = DecryptPrivKey(&privateRepo, 0, []byte(cipher))

	if err != nil {
		t.Fatalf("Wrong status from DecryptPrivKey")
	}
	t.Log(out)
	t.Log(string(out))
	if string(out) != in {
		t.Fatalf("Wrong Encrypt/Decrypt")
	}

}

func TestAesRepo(t *testing.T) {

	aesRepo := KeyRepo[AesKey]{}
	aesRepo.Init(2)
	if len(aesRepo.Keys) != 2 {
		t.Fatalf("Wrong  state of repo after initialization")
	}
	status, err := GenerateAesKey(&aesRepo, 2)

	if status || nil == err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from GenerateKey")
	}

	status, err = GenerateAesKey(&aesRepo, 0)

	if !status || nil != err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	status, err = GenerateAesKey(&aesRepo, 1)

	if !status || nil != err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	_, err = FetchAesKey(&aesRepo, 2)

	if err.Error() != "bank not supported" {
		t.Fatalf("Wrong error from FetchAesKey")
	}

	b64Key1, err := FetchAesKey(&aesRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchAesKey")
	}

	t.Log(b64Key1)
	_, err = LoadAesKey(b64Key1, &aesRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from LoadAesKey")
	}

	b64Key2, err := FetchAesKey(&aesRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchAesKey")
	}

	if b64Key1 != b64Key2 {
		t.Fatalf("Aes Key Inconsistency")
	}

	in := "aslk1234aslk1234"

	cipher, err := EncryptAES(&aesRepo, 0, []byte(in))
	t.Log(in)
	t.Log([]byte(in))

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptAESKey")
	}

	out, err := DecryptAES(&aesRepo, 0, cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptAES")
	}

	t.Log(out)
	t.Log(string(out))

	if string(out) != in {
		t.Fatalf("Wrong Encrypt/Decrypt")
	}

}
