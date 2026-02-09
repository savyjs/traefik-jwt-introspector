package traefik_jwt_introspector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/traefik/traefik/v2/pkg/log"
)

type Config struct {
	ProxyHeaderName string            `json:"proxyHeaderName,omitempty"`
	AuthHeader      string            `json:"authHeader,omitempty"`
	HeaderPrefix    string            `json:"headerPrefix,omitempty"`
	Optional        bool              `json:"optional,omitempty"`
	BaseAuthURL     string            `json:"baseAuthUrl,omitempty"`
	Realms          []RealmConfig     `json:"realms,omitempty"`
	HostRealmMap    map[string]string `json:"hostRealmMap,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type RealmConfig struct {
	RealmName      string `json:"realmName,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	ValidateAPIUrl string `json:"validateAPIUrl,omitempty"`
}

type JWT struct {
	next            http.Handler
	name            string
	proxyHeaderName string
	authHeader      string
	headerPrefix    string
	optional        bool
	realms          map[string]RealmConfig
	hostRealmMap    map[string]string
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
	if len(config.Realms) == 0 {
		return nil, fmt.Errorf("realms cannot be empty")
	}
	if len(config.HostRealmMap) == 0 {
		return nil, fmt.Errorf("hostRealmMap cannot be empty")
	}

	realms := map[string]RealmConfig{}
	for _, realm := range config.Realms {
		if len(realm.RealmName) == 0 {
			return nil, fmt.Errorf("realmName cannot be empty")
		}
		if len(realm.ClientID) == 0 {
			return nil, fmt.Errorf("clientId cannot be empty for realm %s", realm.RealmName)
		}
		if len(realm.ClientSecret) == 0 {
			return nil, fmt.Errorf("clientSecret cannot be empty for realm %s", realm.RealmName)
		}
		if len(realm.ValidateAPIUrl) == 0 {
			if len(config.BaseAuthURL) == 0 {
				return nil, fmt.Errorf("baseAuthUrl cannot be empty when validateAPIUrl is not set for realm %s", realm.RealmName)
			}
			baseURL := strings.TrimRight(config.BaseAuthURL, "/")
			realm.ValidateAPIUrl = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", baseURL, realm.RealmName)
		}
		realms[realm.RealmName] = realm
	}

	hostRealmMap := map[string]string{}
	for host, realmName := range config.HostRealmMap {
		if len(host) == 0 || len(realmName) == 0 {
			return nil, fmt.Errorf("hostRealmMap entries cannot be empty")
		}
		if _, ok := realms[realmName]; !ok {
			return nil, fmt.Errorf("hostRealmMap references unknown realm %s", realmName)
		}
		hostRealmMap[strings.ToLower(host)] = realmName
	}

	return &JWT{
		next:            next,
		name:            name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader:      config.AuthHeader,
		headerPrefix:    config.HeaderPrefix,
		optional:        config.Optional,
		realms:          realms,
		hostRealmMap:    hostRealmMap,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	logger := log.FromContext(req.Context())

	headerValue := req.Header.Get(j.authHeader)
	headerToken := strings.TrimPrefix(headerValue, j.headerPrefix+" ")

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

	host := strings.ToLower(req.Host)
	if len(host) == 0 {
		host = strings.ToLower(req.URL.Host)
	}
	host = strings.Split(host, ":")[0]
	realmName, ok := j.hostRealmMap[host]
	if !ok {
		errorMessageTxt := "realm not configured for host"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}
	realm := j.realms[realmName]

	logger.Debug("Introspecting token", "host", host, "realm", realmName)

	clientID := realm.ClientID
	clientSecret := realm.ClientSecret
	validateAPIUrl := realm.ValidateAPIUrl

	payloadString := "client_secret=" + clientSecret + "&client_id=" + clientID + "&token=" + headerToken

	// Check token via API call
	apiUrl := validateAPIUrl
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

	logger.Debug("Introspection response", "host", host, "realm", realmName, "status", apiRes.StatusCode)

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
