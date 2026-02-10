package traefik_jwt_introspector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	ProxyHeaderName string        `json:"proxyHeaderName,omitempty"`
	AuthHeader      string        `json:"authHeader,omitempty"`
	HeaderPrefix    string        `json:"headerPrefix,omitempty"`
	Optional        bool          `json:"optional,omitempty"`
	BaseAuthURL     string        `json:"baseAuthUrl,omitempty"`
	Realms          []RealmConfig `json:"realms,omitempty"`
	DefaultRealm    string        `json:"defaultRealm,omitempty"`
	LogLevel        string        `json:"logLevel,omitempty"`
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
	defaultRealm    string
	logLevel        string
	infoLogger      *log.Logger
	errorLogger     *log.Logger
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

	infoLogger := log.New(os.Stdout, "", log.LstdFlags)
	errorLogger := log.New(os.Stderr, "", log.LstdFlags)

	return &JWT{
		next:            next,
		name:            name,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader:      config.AuthHeader,
		headerPrefix:    config.HeaderPrefix,
		optional:        config.Optional,
		realms:          realms,
		defaultRealm:    defaultRealm,
		logLevel:        logLevel,
		infoLogger:      infoLogger,
		errorLogger:     errorLogger,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	headerValue := req.Header.Get(j.authHeader)
	headerToken := strings.TrimPrefix(headerValue, j.headerPrefix+" ")
	if len(headerValue) > 0 && !strings.HasPrefix(headerValue, j.headerPrefix+" ") {
		j.logDebug("auth_header_prefix_missing", "authHeader=%s prefix=%s", j.authHeader, j.headerPrefix)
	}

	// Delete the header we inject if they already are in the request
	// to avoid people trying to inject stuff
	req.Header.Del(j.proxyHeaderName)

	if j.optional == true && len(headerToken) == 0 {
		j.logDebug("no_token_optional", "authHeader=%s", j.authHeader)
		j.next.ServeHTTP(res, req)
		return
	} else if j.optional == false && len(headerToken) == 0 {
		j.logInfo("no_token_denied", "authHeader=%s", j.authHeader)
		errorMessageTxt := "access denied"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

	// Determine realm: prefer realm extracted from token "iss" claim, fall back to default
	realmName := ""
	tokenDerivedRealm := tokenRealm(headerToken)
	if tokenDerivedRealm != "" {
		if _, ok := j.realms[tokenDerivedRealm]; ok {
			realmName = tokenDerivedRealm
			j.logDebug("realm_selected_token", "realm=%s", realmName)
		} else {
			realmName = j.defaultRealm
			j.logDebug("realm_selected_default_unknown", "defaultRealm=%s tokenRealm=%s", realmName, tokenDerivedRealm)
		}
	} else {
		realmName = j.defaultRealm
		j.logDebug("realm_selected_default_missing", "defaultRealm=%s", realmName)
	}

	realm := j.realms[realmName]

	j.logDebug("introspect_start", "realm=%s", realmName)

	email := ""
	if j.shouldLog("info") {
		email = tokenEmail(headerToken)
		if email == "" && j.shouldLog("debug") {
			j.logDebug("token_email_missing", "realm=%s", realmName)
		}
	}

	clientID := realm.ClientID
	clientSecret := realm.ClientSecret
	validateAPIUrl := realm.ValidateAPIUrl

	payloadString := "client_secret=" + clientSecret + "&client_id=" + clientID + "&token=" + headerToken

	// Check token via API call
	apiUrl := validateAPIUrl
	j.logDebug("introspect_url", "url=%s realm=%s", apiUrl, realmName)
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
	introspectStart := time.Now()
	apiRes, err := client.Do(newReq)

	if err != nil {
		durationMs := time.Since(introspectStart).Milliseconds()
		j.logError("introspect_request_error", "realm=%s duration_ms=%d error=%s", realmName, durationMs, err.Error())
		res.Header().Set("Content-Type", "application/json")
		errorMessageTxt := "internal error"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	defer apiRes.Body.Close()

	durationMs := time.Since(introspectStart).Milliseconds()
	j.logDebug("introspect_response", "realm=%s status=%d duration_ms=%d", realmName, apiRes.StatusCode, durationMs)

	// Check API response status code
	if apiRes.StatusCode != http.StatusOK {
		j.logError("introspect_non_200", "realm=%s status=%d", realmName, apiRes.StatusCode)
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
		j.logError("introspect_read_error", "realm=%s", realmName)
		errorMessageTxt := "error reading response body"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	var response ApiResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		j.logError("introspect_unmarshal_error", "realm=%s", realmName)
		errorMessageTxt := "error unmarshalling JSON"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	// Check if the response has { "active": true }
	if response.Active {
		if email != "" {
			j.logInfo("token_active_email", "realm=%s email=%s", realmName, email)
		} else {
			j.logInfo("token_active_no_email", "realm=%s", realmName)
		}
		req.Header.Set(j.proxyHeaderName, string(body))
		j.next.ServeHTTP(res, req)
		return
	} else {
		if email != "" {
			j.logInfo("token_inactive_email", "realm=%s email=%s", realmName, email)
		} else {
			j.logInfo("token_inactive_no_email", "realm=%s", realmName)
		}
		errorMessageTxt := "invalid token"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

}

func tokenEmail(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	if emailValue, ok := claims["email"]; ok {
		if email, ok := emailValue.(string); ok {
			return email
		}
	}

	return ""
}

// tokenRealm extracts a Keycloak realm name from the token's 'iss' claim.
// It returns the realm name if the issuer contains the pattern '/realms/{realm}',
// otherwise it returns an empty string.
func tokenRealm(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	issValue, ok := claims["iss"]
	if !ok {
		return ""
	}
	issStr, ok := issValue.(string)
	if !ok {
		return ""
	}

	// Look for '/realms/{realm}' anywhere in the issuer string
	marker := "/realms/"
	if idx := strings.Index(issStr, marker); idx >= 0 {
		remainder := issStr[idx+len(marker):]
		if len(remainder) == 0 {
			return ""
		}
		realm := strings.SplitN(remainder, "/", 2)[0]
		realm = strings.TrimSpace(realm)
		return realm
	}

	return ""
}

func isValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "error", "none", "all":
		return true
	default:
		return false
	}
}

func (j *JWT) logDebug(event string, format string, args ...interface{}) {
	if !j.shouldLog("debug") {
		return
	}
	if j.infoLogger == nil {
		j.infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	}
	j.infoLogger.Printf("DEBUG event=%s %s", event, fmt.Sprintf(format, args...))
}

func (j *JWT) logInfo(event string, format string, args ...interface{}) {
	if !j.shouldLog("info") {
		return
	}
	if j.infoLogger == nil {
		j.infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	}
	j.infoLogger.Printf("INFO event=%s %s", event, fmt.Sprintf(format, args...))
}

func (j *JWT) logError(event string, format string, args ...interface{}) {
	if !j.shouldLog("error") {
		return
	}
	if j.errorLogger == nil {
		j.errorLogger = log.New(os.Stderr, "", log.LstdFlags)
	}
	j.errorLogger.Printf("ERROR event=%s %s", event, fmt.Sprintf(format, args...))
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
