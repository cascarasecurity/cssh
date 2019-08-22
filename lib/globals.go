package lib

import (
	"os/user"
	"path/filepath"
)

var Client_ID = "338194013238-p2crol97smqj7d21q1ba15ln4fmijh0n.apps.googleusercontent.com"
var Client_Secret = "78ilrmRKSS0skXU_pDKfKQx1"

func GetSSHPrivateKey() string {
	usr, _ := user.Current()
	dir := usr.HomeDir
	return filepath.Join(dir, ".ssh/cascarakey")
}

func GetSSHPublicKey() string {
	usr, _ := user.Current()
	dir := usr.HomeDir
	return filepath.Join(dir, ".ssh/cascarakey.pub")
}

func GetSSHSignedKey() string {
	usr, _ := user.Current()
	dir := usr.HomeDir
	return filepath.Join(dir, ".ssh/cascarakey-cert.pub")
}

func GetDomain() string {
	//return "http://localhost:5000"
	return "https://keys.cascarasecurity.com"
}