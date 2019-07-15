package oauth

import (
	"fmt"

	"github.com/cascarasecurity/cssh/lib"
	"github.com/pkg/browser"
	"net/http"
	"log"
	"context"
)

var scope = "https://www.googleapis.com/auth/userinfo.email"
var endpoint = "https://accounts.google.com/o/oauth2/v2/auth"

var htmlTemplate = `
<style>
    .outer {
        display: table;
        position: absolute;
        top: 0;
        left: 0;
        height: 100%;
        width: 100%;
    }
    
    .middle {
        display: table-cell;
        vertical-align: middle;
    }
    
    .inner {
        margin-left: auto;
        margin-right: auto;
        width: 400px;
        /*whatever width you want*/
    }
    
    .icon {
        width: 10%;
        color: #5fba7d;
    }
</style>

<div class="outer">
    <div class="middle">
        <div class="inner">
            <center>
                <h1>%s</h1>
                <p>
                    Please return to cssh to complete your ssh connection
                </p>
                <!-- Font Awesome Icon. License here: https://fontawesome.com/license -->
                <div class="icon">
                    <svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="check-circle" class="svg-inline--fa fa-check-circle fa-w-16" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
                        <path fill="currentColor" d="M504 256c0 136.967-111.033 248-248 248S8 392.967 8 256 119.033 8 256 8s248 111.033 248 248zM227.314 387.314l184-184c6.248-6.248 6.248-16.379 0-22.627l-22.627-22.627c-6.248-6.249-16.379-6.249-22.628 0L216 308.118l-70.059-70.059c-6.248-6.248-16.379-6.248-22.628 0l-22.627 22.627c-6.248 6.248-6.248 16.379 0 22.627l104 104c6.249 6.249 16.379 6.249 22.628.001z"></path>
                    </svg>
                </div>
            </center>
        </div>
    </div>
</div>
`

func GetAccessToken() (string, error) {
	srv, codeChan := startHttpServer()

	url := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=%s&access_type=offline&redirect_uri=http://localhost:2242/redirect",
	endpoint, lib.Client_ID, scope)
	err := browser.OpenURL(url)
	if err != nil {
		fmt.Printf("Please go to this URL to authorize cssh with your Google account: \nURL: %s", url)
	}

	code := <-codeChan
	// Ignore the potential error from shutting down the server and just keep running. It will shut down
	// eventually since cssh is a short lived program.
	srv.Shutdown(context.Background())
	if code == "" {
		return code, fmt.Errorf("Failed to get an auth token from Google. Did you complete the OAuth flow correctly?")
	}
	return code, nil
}

func startHttpServer() (*http.Server, chan string) {
	srv := &http.Server{Addr: ":2242"}

	codeChan := make(chan string, 0)
	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		codes, ok := r.URL.Query()["code"]
		if ok && len(codes) == 1 {
			codeChan <- codes[0]
			w.Write([]byte(fmt.Sprintf(htmlTemplate, "Auth Complete")))
		} else {
			codeChan <- ""
			w.Write([]byte(fmt.Sprintf(htmlTemplate, "Auth Error")))
		}
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %s", err)
		}
	}()

	return srv, codeChan
}

