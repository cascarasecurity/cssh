package main

import (
	"github.com/cascarasecurity/cssh/oauth"
	"github.com/cascarasecurity/cssh/ssh_util"
	"github.com/cascarasecurity/cssh/lib"
	"io/ioutil"
	"strconv"
	"os"
	"golang.org/x/crypto/ssh"
	"time"
	"os/exec"
)

var Cascara_Org_ID string = "82"	// TODO: Inject this

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func GetOrgID() (int, error) {
	return strconv.Atoi(Cascara_Org_ID)
}

func main() {
	if needToRenewCert() {
		token, err := oauth.GetAccessToken()
		check(err)

		// TODO: Cache the token?

		err = ssh_util.MakeSSHKeyPair(lib.GetSSHPublicKey(), lib.GetSSHPrivateKey())
		check(err)

		pubKey, err := ioutil.ReadFile(lib.GetSSHPublicKey())
		check(err)

		orgId, err := GetOrgID()
		check(err)

		signed, err := ssh_util.SignKey(orgId, string(pubKey), token)
		check(err)

		err = ioutil.WriteFile(lib.GetSSHSignedKey(), []byte(signed), 0600)
		check(err)
	}

	argumentList := []string{"-i", lib.GetSSHPrivateKey(), "-o", "IdentitiesOnly=yes"}
	argumentList = append(argumentList, os.Args[1:]...)

	cmd := exec.Command("ssh", argumentList...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
}

func needToRenewCert() bool {
	_, err1 := os.Stat(lib.GetSSHPublicKey())
	_, err2 := os.Stat(lib.GetSSHPrivateKey())
	_, err3 := os.Stat(lib.GetSSHPrivateKey())
	if os.IsNotExist(err1) || os.IsNotExist(err2) || os.IsNotExist(err3) {
		return true
	}

	data, err := ioutil.ReadFile(lib.GetSSHSignedKey())
	if err != nil {
		return true
	}

	k, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return true
	}
	// See: https://github.com/golang/go/issues/22046
	cert := k.(*ssh.Certificate)

	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	validAfter := time.Unix(int64(cert.ValidAfter), 0)

	return time.Now().Before(validAfter) || time.Now().After(validBefore)
}
