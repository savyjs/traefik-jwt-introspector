package traefik_jwt_introspector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	ProxyHeaderName string            `json:"proxyHeaderName,omitempty"`
	AuthHeader      string            `json:"authHeader,omitempty"`
	HeaderPrefix    string            `json:"headerPrefix,omitempty"`
	Optional        bool              `json:"optional,omitempty"`
	BaseAuthURL     string            `json:"baseAuthUrl,omitempty"`
	Realms          []RealmConfig     `json:"realms,omitempty"`
	OriginRealmMap  map[string]string `json:"originRealmMap,omitempty"`
	DefaultRealm    string            `json:"defaultRealm,omitempty"`
	LogLevel        string            `json:"logLevel,omitempty"`
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
	originRealmMap  map[string]string
	defaultRealm    string
	logLevel        string
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
	logLevel := strings.ToLower(strings.TrimSpace(config.LogLevel))
	if len(logLevel) == 0 {
		logLevel = "none"
	}
	if !isValidLogLevel(logLevel) {
		return nil, fmt.Errorf("invalid logLevel %q", config.LogLevel)
	}
	if len(config.Realms) == 0 {
		return nil, fmt.Errorf("realms cannot be empty")
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

	defaultRealm := strings.TrimSpace(config.DefaultRealm)
	if len(defaultRealm) == 0 {
		defaultRealm = config.Realms[0].RealmName
	}
	if len(defaultRealm) > 0 {
		if _, ok := realms[defaultRealm]; !ok {
			return nil, fmt.Errorf("defaultRealm references unknown realm %s", defaultRealm)
		}
	}

	originRealmMap := map[string]string{}
	for host, realmName := range config.OriginRealmMap {
		if len(host) == 0 || len(realmName) == 0 {
			return nil, fmt.Errorf("originRealmMap entries cannot be empty")
		}
		if _, ok := realms[realmName]; !ok {
			return nil, fmt.Errorf("originRealmMap references unknown realm %s", realmName)
		}
		originRealmMap[strings.ToLower(host)] = realmName
	}

	return &JWT{
		next:            next,
		name:            name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader:      config.AuthHeader,
		headerPrefix:    config.HeaderPrefix,
		optional:        config.Optional,
		realms:          realms,
		originRealmMap:  originRealmMap,
		defaultRealm:    defaultRealm,
		logLevel:        logLevel,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

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

	originHost, err := originHost(req)
	if err != nil {
		j.logError("jwt-introspector invalid origin error=%s", err.Error())
		errorMessageTxt := "origin not configured"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}
	originLabel := originHost
	if len(originLabel) == 0 {
		originLabel = "missing"
	}

	realmName := ""
	ok := false
	if len(originHost) > 0 {
		realmName, ok = j.originRealmMap[originHost]
	}
	if !ok {
		if len(j.defaultRealm) == 0 {
			j.logError("jwt-introspector realm not configured origin=%s", originLabel)
			errorMessageTxt := "realm not configured"
			http.Error(res, errorMessageTxt, http.StatusUnauthorized)
			return
		}
		realmName = j.defaultRealm
		if len(originHost) == 0 {
			j.logDebug("jwt-introspector origin missing using default realm=%s", realmName)
		} else {
			j.logDebug("jwt-introspector origin not mapped using default realm=%s origin=%s", realmName, originLabel)
		}
	}
	realm := j.realms[realmName]

	j.logDebug("jwt-introspector introspecting origin=%s realm=%s", originLabel, realmName)

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
		j.logError("jwt-introspector introspection request error origin=%s realm=%s", originLabel, realmName)
		res.Header().Set("Content-Type", "application/json")
		errorMessageTxt := "internal error"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	defer apiRes.Body.Close()

	j.logDebug("jwt-introspector introspection response origin=%s realm=%s status=%d", originLabel, realmName, apiRes.StatusCode)

	// Check API response status code
	if apiRes.StatusCode != http.StatusOK {
		j.logError("jwt-introspector introspection non-200 origin=%s realm=%s status=%d", originLabel, realmName, apiRes.StatusCode)
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
		j.logError("jwt-introspector read response error origin=%s realm=%s", originLabel, realmName)
		errorMessageTxt := "error reading response body"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	var response ApiResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		j.logError("jwt-introspector unmarshal error origin=%s realm=%s", originLabel, realmName)
		errorMessageTxt := "error unmarshalling JSON"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	// Check if the response has { "active": true }
	if response.Active {
		j.logInfo("jwt-introspector token active origin=%s realm=%s", originLabel, realmName)
		req.Header.Set(j.proxyHeaderName, string(body))
		j.next.ServeHTTP(res, req)
		return
	} else {
		j.logInfo("jwt-introspector token inactive origin=%s realm=%s", originLabel, realmName)
		errorMessageTxt := "invalid token"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

}

func originHost(req *http.Request) (string, error) {
	origin := strings.TrimSpace(req.Header.Get("Origin"))
	if len(origin) == 0 {
		return "", nil
	}

	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid origin")
	}
	host := strings.ToLower(parsed.Host)
	host = strings.Split(host, ":")[0]
	if len(host) == 0 {
		return "", fmt.Errorf("invalid origin")
	}
	return host, nil
}

func isValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "error", "none", "all":
		return true
	default:
		return false
	}
}

func (j *JWT) logDebug(format string, args ...interface{}) {
	if !j.shouldLog("debug") {
		return
	}
	log.Printf("DEBUG %s", fmt.Sprintf(format, args...))
}

func (j *JWT) logInfo(format string, args ...interface{}) {
	if !j.shouldLog("info") {
		return
	}
	log.Printf("INFO %s", fmt.Sprintf(format, args...))
}

func (j *JWT) logError(format string, args ...interface{}) {
	if !j.shouldLog("error") {
		return
	}
	log.Printf("ERROR %s", fmt.Sprintf(format, args...))
}

func (j *JWT) shouldLog(level string) bool {
	current := logLevelPriority(j.logLevel)
	required := logLevelPriority(level)
	return current >= required
}

func logLevelPriority(level string) int {
	switch level {
	case "none":
		return 0
	case "error":
		return 1
	case "info":
		return 2
	case "debug":
		return 3
	case "all":
		return 4
	default:
		return 0
	}
}
