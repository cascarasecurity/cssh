package ssh_util

import (
	"crypto/rsa"
	"crypto/rand"
	"os"
	"encoding/pem"
	"io/ioutil"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

func MakeSSHKeyPair(pubKeyPath string, privateKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer privateKeyFile.Close()
	if err != nil {
		return err
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(pub), 0600)
}
