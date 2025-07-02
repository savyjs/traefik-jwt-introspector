package traefik_jwt_introspector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type Config struct {
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader      string `json:"authHeader,omitempty"`
	HeaderPrefix    string `json:"headerPrefix,omitempty"`
	Optional        bool   `json:"optional,omitempty"`
	ValidateAPIUrl  string `json:"validateAPIUrl,omitempty"`
	ClientID        string `json:"clientID,omitempty"`
	ClientSecret    string `json:"clientSecret,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next            http.Handler
	name            string
	proxyHeaderName string
	authHeader      string
	headerPrefix    string
	optional        bool
	clientID        string
	clientSecret    string
	validateAPIUrl  string
}

type ApiResponse struct {
	Active bool `json:"active"`
	// Add other fields if necessary
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
		return nil, fmt.Errorf("validateAPIUrl cannot be empty")
	}

	return &JWT{
		next:            next,
		name:            name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader:      config.AuthHeader,
		headerPrefix:    config.HeaderPrefix,
		optional:        config.Optional,
		clientID:        config.ClientID,
		clientSecret:    config.ClientSecret,
		validateAPIUrl:  config.ValidateAPIUrl,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

//     // Retrieve the logger from the context
//     logger := log.FromContext(req.Context())
//
//     // Log a debug message
//     logger.Debug("Processing request", "url", req.URL.String())

    // Continue with your plugin logic...


	headerToken := strings.TrimPrefix(req.Header.Get(j.authHeader), "Bearer ")

	// Delete the header we inject if they already are in the request
	// to avoid people trying to inject stuff
	req.Header.Del(j.proxyHeaderName)

	if j.optional == true && len(headerToken) == 0 {
		j.next.ServeHTTP(res, req)
		return
	} else if j.optional == false && len(headerToken) == 0 {
		errorMessageTxt := "access denied"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

	payloadString := "client_secret=" + j.clientSecret + "&client_id=" + j.clientID + "&token=" + headerToken

	// Check token via API call
	apiUrl := j.validateAPIUrl
	payload := strings.NewReader(payloadString)

	newReq, err := http.NewRequest("POST", apiUrl, payload)

	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		errorMessageTxt := "internal error"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	newReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	apiRes, err := client.Do(newReq)

	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		errorMessageTxt := "internal error"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	defer apiRes.Body.Close()

	// Check API response status code
	if apiRes.StatusCode != http.StatusOK {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(apiRes.StatusCode)
		body, err := ioutil.ReadAll(apiRes.Body)
		if err != nil {
			errorMessageTxt := "internal error"
			http.Error(res, errorMessageTxt, http.StatusInternalServerError)
			return
		}

		errorMessageTxt := "internal error" + string(body)
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	body, err := ioutil.ReadAll(apiRes.Body)
	if err != nil {
		errorMessageTxt := "error reading response body"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	var response ApiResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		errorMessageTxt := "error unmarshalling JSON"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	// Check if the response has { "active": true }
	if response.Active {
		req.Header.Set(j.proxyHeaderName, string(body))
		j.next.ServeHTTP(res, req)
		return
	} else {
		errorMessageTxt := "invalid token"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

}
