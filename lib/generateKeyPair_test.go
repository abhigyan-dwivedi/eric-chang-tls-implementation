package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestGenerateNewKeyPair(t *testing.T) {
	testString := []byte("A quick brown fox jumps over a lazy dog.")
	got, err := GenerateNewKeyPair(2048)
	if err != nil {
		t.Errorf("GenerateNewKeyPair() error = %v", err)
		return
	}

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, &got.PublicKey, testString)

	if err != nil {
		t.Errorf("Generating Cipher text errored = %v", err)
		return
	}

	t.Log("\nCipher Text:\n:", cipherText)

	recoveredBytes, err := rsa.DecryptPKCS1v15(rand.Reader, got, cipherText)

	if err != nil {
		t.Errorf("Generating recovered text from the cipher  text errored = %v", err)
		return
	}

	recString := string(recoveredBytes)
	if strings.Compare(string(testString), recString) == 0 {
		t.Log("Original Message matches with decrypted one.")
	}
}
