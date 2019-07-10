package lib

import (
	"os/user"
	"path/filepath"
)

var Client_ID = "338194013238-dv5vitutvgevc9rn316j9430mhcka1qg.apps.googleusercontent.com"
var Client_Secret = "BQm6CLrO_Mf7NrAwXi1tN9_J"

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
	return "http://localhost:5000"
	//return "https://keys.cascarasecurity.com"
}