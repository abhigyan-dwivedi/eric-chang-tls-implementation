package lib

import (
	"crypto/rand"
	"crypto/rsa"
)

//GenerateNewKeyPair Function Generates a public private keypair and reeturns  a
//rsa.PrivateKey ptr and error in response
func GenerateNewKeyPair(bits int) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privKey, err
}
