package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
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

	b64PubKey2, _ := FetchPubKey(&publicRepo, 0)

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

	cipher, err := EncryptAESBlock(&aesRepo, 0, []byte(in))
	t.Log(in)
	t.Log([]byte(in))

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptAESBlock")
	}

	out, err := DecryptAESBlock(&aesRepo, 0, cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptAES")
	}

	t.Log(out)
	t.Log(string(out))

	if string(out) != in {
		t.Fatalf("Wrong Encrypt/Decrypt")
	}

}

func TestAes(t *testing.T) {

	aesRepo := KeyRepo[AesKey]{}
	aesRepo.Init(1)

	status, err := GenerateAesKey(&aesRepo, 0)

	if !status || nil != err {
		t.Fatalf("Wrong status from GenerateKey")
	}

	// first step is to create a slice of bytes with the desired length
	in := make([]byte, 1024*1024*2)
	// then we can call rand.Read.
	_, err = rand.Read(in)
	if err != nil {
		t.Fatalf("Wrong status from rand.Read")
	}
	t.Log(in)

	cipher, err := EncryptAES(&aesRepo, 0, in)

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from EncryptAES")
	}

	out, err := DecryptAES(&aesRepo, 0, cipher)

	if err != nil {
		t.Fatalf("Wrong status from DecryptAES")
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("Data not consistent")
	}
	t.Log(out)

}

func TestSignature(t *testing.T) {

	privateRepo := KeyRepo[rsa.PrivateKey]{}
	publicRepo := KeyRepo[rsa.PublicKey]{}
	privateRepo.Init(1)
	publicRepo.Init(1)

	status, err := GeneratePrivKey(&privateRepo, 0, 512)

	if !status || nil != err {
		t.Fatalf("Wrong status from GenerateKey")
	}
	b64Key1, err := FetchPrivKey(&privateRepo, 0)

	if err != nil {
		t.Fatalf("Wrong status from FetchPrivKey")
	}

	t.Log(b64Key1)

	in := "aslk1234"
	h := sha256.New()

	h.Write([]byte(in))

	bs := h.Sum(nil)

	cipher, err := SignHashMsg(&privateRepo, 0, crypto.SHA256, bs)
	t.Log(in)
	t.Log([]byte(in))

	t.Log(cipher)

	if err != nil {
		t.Fatalf("Wrong status from SignHashMsg")
	}

	ExtractPubKey(&privateRepo.Keys[0], &publicRepo.Keys[0])

	b64Key2, _ := FetchPubKey(&publicRepo, 0)
	t.Log(b64Key2)

	err = VerifyHashMsg(&publicRepo, 0, crypto.SHA256, bs, cipher)

	if err != nil {
		t.Fatalf("Wrong status from VerifyHashMsg")
	}

}

func TestHash(t *testing.T) {
	type TestVector struct {
		msg  string
		hash string
		alg  crypto.Hash
	}

	toHex :=
		func(in []byte) string {
			var hex []string
			for i := 0; i < len(in); i++ {
				hex = append(hex, fmt.Sprintf("%02x", in[i]))
			}

			return strings.Join(hex, "")
		}

	testVector := []TestVector{ // echo -n "aslk12" | sha256sum 7ee22696d9379fdcb90a526616c7b9ceec9c43183b010b65e0da160868c31cf0
		{msg: "aslk12", hash: "7ee22696d9379fdcb90a526616c7b9ceec9c43183b010b65e0da160868c31cf0", alg: crypto.SHA256},
		{msg: "aslk1234", hash: "c5731671e63c051e177606da7f247c16", alg: crypto.MD5}, // echo -n "aslk1234" | md5sum 5731671e63c051e177606da7f247c16
		//echo aslk98 | sha512sum e6dd9a011e4600cb13a014881a0251c8e136f0a36f6705965978e3227db88fa59b5c0333c02d5ba2da04b4ff671ed249cf66dfc1e17aa211ecb8cd1472b3d1b6
		{msg: "aslk98", hash: "e6dd9a011e4600cb13a014881a0251c8e136f0a36f6705965978e3227db88fa59b5c0333c02d5ba2da04b4ff671ed249cf66dfc1e17aa211ecb8cd1472b3d1b6", alg: crypto.SHA512},
	}

	for i := 0; i < len(testVector); i++ {

		out, err := HashBlock(testVector[i].alg, []byte(testVector[i].msg))
		if err != nil {
			t.Fatalf("Wrong Status from HASH 256")
		}

		if toHex(out) != testVector[i].hash || err != nil {
			t.Log(toHex(out))
			t.Log(testVector[i].hash)

			t.Fatalf("Wrong status from " + testVector[i].alg.String())

		}
	}

}
