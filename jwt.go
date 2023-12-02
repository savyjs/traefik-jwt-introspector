package traefik_jwt_introspector

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
	"io/ioutil"
)

type Config struct {
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader string `json:"authHeader,omitempty"`
	HeaderPrefix string `json:"headerPrefix,omitempty"`
	Optional bool `json:"optional,omitempty"`
	ValidateAPIUrl string `json:"validateAPIUrl,omitempty"`
	ClientID string `json:"clientID,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
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
		config.ValidateAPIUrl = "http://api/api/auth/validate-access-token"
	}

	return &JWT{
		next:		next,
		name:		name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader: config.AuthHeader,
		headerPrefix: config.HeaderPrefix,
		optional: config.Optional,
		clientID: config.ClientID,
		clientSecret: config.ClientSecret,
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

	payload := strings.NewReader("client_secret=" + j.clientID + "&client_id=" + j.ClientSecret  + "&token=" + headerToken)
	
	newReq, err := http.NewRequest("POST", apiUrl, nil)
	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusInternalServerError)
		errorMessage := map[string]string{"detail": "Error creating API request"}
		json.NewEncoder(res).Encode(errorMessage)
		return
	}
	
	// newReq.Header.Add("Authorization", headerToken)
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
		body, err := ioutil.ReadAll(apiRes.Body)
	        if err != nil {
	            errorMessageTxt := "Invalid Token"
	        }
				
		errorMessageTxt := string(body)
		errorMessage := map[string]string{"detail": errorMessageTxt}
		json.NewEncoder(res).Encode(errorMessage)
		return
	}

	body, err := ioutil.ReadAll(apiRes.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var response ApiResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	// Check if the response has { "active": true }
	if response.Active {
		j.next.ServeHTTP(res, req)
		return
	} else {
		errorMessageTxt := "The Token is not active."
	}

	

	
	// If we reach this point, the token is valid, so we can continue with the request
	j.next.ServeHTTP(res, req)
	return
}
