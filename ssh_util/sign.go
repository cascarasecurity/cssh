package ssh_util

import (
	"strconv"
	"encoding/json"
	"net/http"
	"bytes"
	"io/ioutil"
	"fmt"
	"github.com/cascarasecurity/cssh/lib"
)

func SignKey(orgId int, pubKey string, oauthToken string) (string, error) {
	values := map[string]string{"ssh_pub_key": pubKey, "org_id": strconv.Itoa(orgId), "oauth_token": oauthToken}

	jsonValue, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/sign_key", lib.GetDomain()),
			"application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	status, parsedBody, err := parseServerResponse(string(body))
	if err != nil {
		return "", err
	}
	if !status {
		return "", fmt.Errorf("Got bad status code in SignKey! Body=%s", parsedBody.(string))
	}
	return parsedBody.(string), nil
}

func parseServerResponse(body string) (status bool, respBody interface{}, err error) {
	m := map[string]interface{}{}
	err = json.Unmarshal([]byte(body), &m)
	if err != nil {
		return false, nil, err
	}
	return m["status"].(bool), m["body"], nil
}

