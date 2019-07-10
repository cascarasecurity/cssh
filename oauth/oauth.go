package oauth

import (
	"fmt"

	"github.com/cascarasecurity/cssh/lib"
	"github.com/pkg/browser"
	"bufio"
	"os"
)

var scope = "https://www.googleapis.com/auth/userinfo.email"
var endpoint = "https://accounts.google.com/o/oauth2/v2/auth"

func GetAccessToken() (string, error) {
	url := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=%s&access_type=offline&redirect_uri=urn:ietf:wg:oauth:2.0:oob",
	endpoint, lib.Client_ID, scope)
	err := browser.OpenURL(url)
	if err != nil {
		fmt.Printf("Please go to this URL to authorize cssh with your Google account: \nURL: %s", url)
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the code displayed in the browser: ")
	return reader.ReadString('\n')
}