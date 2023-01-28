package traefik_jwt_optional_api_validator

import (
	"context"
	"fmt"
	"strings"
	"net/http"
	"strconv"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"time"
	"encoding/json"
)

type Config struct {
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader string `json:"authHeader,omitempty"`
	HeaderPrefix string `json:"headerPrefix,omitempty"`
	Optional bool `json:"optional,omitempty"`
	ValidateAPIUrl string `json:"validateAPIUrl,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next						http.Handler
	name						string
	proxyHeaderName string
	authHeader 			string
	headerPrefix		string
	optional		bool
	validateAPIUrl	string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.ProxyHeaderName) == 0 {
		config.ProxyHeaderName = "injectedPayload"
	}
	if len(config.AuthHeader) == 0 {
		config.AuthHeader = "Authorization"
	}
	if len(config.HeaderPrefix) == 0 {
		config.HeaderPrefix = "Bearer"
	}
	if len(config.ValidateAPIUrl) == 0 {
		config.ValidateAPIUrl = "http://api/api/auth/validate-access-token"
	}

	return &JWT{
		next:		next,
		name:		name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader: config.AuthHeader,
		headerPrefix: config.HeaderPrefix,
		optional: config.Optional,
		validateAPIUrl: config.ValidateAPIUrl,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(j.authHeader)

	// Delete the header we inject if they already are in the request
	// to avoid people trying to inject stuff
	req.Header.Del(j.proxyHeaderName)

   if j.optional == true && len(headerToken) == 0{
       j.next.ServeHTTP(res, req)
       return
    }

	// Check token via API call
	apiUrl := j.validateAPIUrl
	newReq, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusInternalServerError)
		errorMessage := map[string]string{"detail": "Error creating API request"}
		json.NewEncoder(res).Encode(errorMessage)
		return
	}
	newReq.Header.Add("Authorization", headerToken)
	client := &http.Client{}
	apiRes, err := client.Do(newReq)
	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusInternalServerError)
		errorMessage := map[string]string{"detail": "Error calling API"}
		json.NewEncoder(res).Encode(errorMessage)
		return
	}
	defer apiRes.Body.Close()

	// Check API response status code
	if apiRes.StatusCode != http.StatusOK {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(apiRes.StatusCode)
		errorMessage := map[string]string{"detail": "Invalid Token"}
		json.NewEncoder(res).Encode(errorMessage)
		return
	}

	// If we reach this point, the token is valid, so we can continue with the request
	j.next.ServeHTTP(res, req)
	return
}
