package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/aftaab60/store_oauth_go/errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "accessToken"
	oauthApiBaseUrl  = ":8080/oauth"
)

var (
	oauthRestClient = http.Client{
		Timeout: time.Millisecond * 100,
	}
)

type AccessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"userId"`
	ClientId int64  `json:"clientId"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	accessToken, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			//treat request as public request instead of breaking flow
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", accessToken.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", accessToken.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*AccessToken, *errors.RestErr) {
	response, err := oauthRestClient.Get(fmt.Sprintf(oauthApiBaseUrl+"/accessToken/%s", accessTokenId))
	if err != nil {
		return nil, errors.NewInternalServerError("Invalid rest-client response when trying to get access token")
	}
	byteResponse, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.NewInternalServerError("Error reading getAccessToken response")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(byteResponse, &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface in getAccessToken response")
		}
		return nil, &restErr
	}

	var accessToken AccessToken
	if err := json.Unmarshal(byteResponse, &accessToken); err != nil {
		return nil, errors.NewInternalServerError("Error unmarshalling get accessToken response")
	}
	return &accessToken, nil
}
