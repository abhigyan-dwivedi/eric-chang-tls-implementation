package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
)

// A second trait of public private key-pairs is the ability to create a digital signature
// for a given message. These signatures can be used to ensure the validity of the document it signs.

// To to this, the document is run through a hashing algorithm (we’ll use SHA256),
// then the private key computes a signature for the hashed results.

// The public key can then confirm, again through math we’ll ignore,
// if its private key combined with a particular hash would have created that signature.
// Here’s what that looks like using crypto/rsa.

// GenerateDigitalSignatureUsingTheKeyPair
func GenerateDigitalSignatureUsingTheKeyPair(document string, privKey *rsa.PrivateKey) ([]byte, []byte, error) {
	hash := sha256.Sum256([]byte(document))

	//Generate the signature using the private Key.
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])

	if err != nil {
		log.Fatalf("Signature not created properly %#v", err)
		return nil, nil, err
	}
	return hash[:], signature, nil
}

func VerifyDocumentSigntureAgainstKey(document, signature []byte, pubKey *rsa.PublicKey) func(*rsa.PublicKey, []byte, []byte) error {
	return func(pubKey *rsa.PublicKey, document, signature []byte) error {
		hash := sha256.Sum256(document)
		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
		if err != nil {
			return err
		}
		return nil
	}
}
