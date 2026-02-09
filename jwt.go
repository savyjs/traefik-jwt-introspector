package traefik_jwt_introspector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	ProxyHeaderName       string            `json:"proxyHeaderName,omitempty"`
	AuthHeader            string            `json:"authHeader,omitempty"`
	HeaderPrefix          string            `json:"headerPrefix,omitempty"`
	Optional              bool              `json:"optional,omitempty"`
	BaseAuthURL           string            `json:"baseAuthUrl,omitempty"`
	Realms                []RealmConfig     `json:"realms,omitempty"`
	OriginRealmMap        map[string]string `json:"originRealmMap,omitempty"`
	OriginHeader          string            `json:"originHeader,omitempty"`
	OriginHeaderFallbacks []string          `json:"originHeaderFallbacks,omitempty"`
	DefaultRealm          string            `json:"defaultRealm,omitempty"`
	LogLevel              string            `json:"logLevel,omitempty"`
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
	originHeaders   []string
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
	originHeaders := normalizeOriginHeaders(config.OriginHeader, config.OriginHeaderFallbacks)
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
		originRealmMap:  originRealmMap,
		originHeaders:   originHeaders,
		defaultRealm:    defaultRealm,
		logLevel:        logLevel,
		infoLogger:      infoLogger,
		errorLogger:     errorLogger,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	headerValue := req.Header.Get(j.authHeader)
	headerToken := strings.TrimPrefix(headerValue, j.headerPrefix+" ")

	// Delete the header we inject if they already are in the request
	// to avoid people trying to inject stuff
	req.Header.Del(j.proxyHeaderName)

	if j.optional == true && len(headerToken) == 0 {
		j.logDebug("jwt-introspector no token and optional; skipping")
		j.next.ServeHTTP(res, req)
		return
	} else if j.optional == false && len(headerToken) == 0 {
		j.logInfo("jwt-introspector no token; access denied")
		errorMessageTxt := "access denied"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

	originHost, originHeader, err := originHost(req, j.originHeaders)
	if err != nil {
		j.logDebug("jwt-introspector invalid origin header=%s error=%s", originHeader, err.Error())
		originHost = ""
	}
	originLabel := originHost
	if len(originLabel) == 0 {
		originLabel = "missing"
	}
	if len(originHost) == 0 && len(originHeader) == 0 {
		j.logDebug("jwt-introspector origin header missing headers=%s", strings.Join(j.originHeaders, ","))
	}

	// Determine realm: prefer realm extracted from token "iss" claim, fall back to origin mapping, then default
	realmName := ""
	// Attempt to extract realm from token's issuer (iss)
	tokenDerivedRealm := tokenRealm(headerToken)
	if tokenDerivedRealm != "" {
		if _, ok := j.realms[tokenDerivedRealm]; ok {
			realmName = tokenDerivedRealm
			j.logDebug("jwt-introspector realm derived from token iss realm=%s", realmName)
		} else {
			j.logDebug("jwt-introspector realm from token iss not recognized realm=%s", tokenDerivedRealm)
		}
	}

	ok := false
	if realmName == "" {
		if len(originHost) > 0 {
			realmName, ok = j.originRealmMap[originHost]
		}
		if !ok {
			realmName = j.defaultRealm
			if len(originHost) == 0 {
				j.logDebug("jwt-introspector origin missing using default realm=%s", realmName)
			} else {
				j.logDebug("jwt-introspector origin not mapped using default realm=%s origin=%s", realmName, originLabel)
			}
		} else {
			if len(originHeader) > 0 && len(j.originHeaders) > 0 && !strings.EqualFold(originHeader, j.originHeaders[0]) {
				j.logDebug("jwt-introspector using origin fallback header=%s", originHeader)
			}
			j.logDebug("jwt-introspector origin mapped header=%s origin=%s realm=%s", originHeader, originLabel, realmName)
		}
	} else {
		j.logDebug("jwt-introspector using realm from token=%s", realmName)
	}

	realm := j.realms[realmName]

	j.logDebug("jwt-introspector introspecting origin=%s realm=%s", originLabel, realmName)

	email := ""
	if j.shouldLog("info") {
		email = tokenEmail(headerToken)
		if email == "" && j.shouldLog("debug") {
			j.logDebug("jwt-introspector token email not present")
		}
	}

	clientID := realm.ClientID
	clientSecret := realm.ClientSecret
	validateAPIUrl := realm.ValidateAPIUrl

	payloadString := "client_secret=" + clientSecret + "&client_id=" + clientID + "&token=" + headerToken

	// Check token via API call
	apiUrl := validateAPIUrl
	j.logDebug("jwt-introspector introspection url=%s realm=%s", apiUrl, realmName)
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
		if email != "" {
			j.logInfo("jwt-introspector token active origin=%s realm=%s email=%s", originLabel, realmName, email)
		} else {
			j.logInfo("jwt-introspector token active origin=%s realm=%s", originLabel, realmName)
		}
		req.Header.Set(j.proxyHeaderName, string(body))
		j.next.ServeHTTP(res, req)
		return
	} else {
		if email != "" {
			j.logInfo("jwt-introspector token inactive origin=%s realm=%s email=%s", originLabel, realmName, email)
		} else {
			j.logInfo("jwt-introspector token inactive origin=%s realm=%s", originLabel, realmName)
		}
		errorMessageTxt := "invalid token"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

}

func normalizeOriginHeaders(primary string, fallbacks []string) []string {
	headers := []string{}
	seen := map[string]struct{}{}

	addHeader := func(header string) {
		header = strings.TrimSpace(header)
		if len(header) == 0 {
			return
		}
		key := strings.ToLower(header)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		headers = append(headers, http.CanonicalHeaderKey(header))
	}

	addHeader(primary)
	for _, fallback := range fallbacks {
		addHeader(fallback)
	}
	if len(headers) == 0 {
		addHeader("Origin")
	}

	return headers
}

func originHost(req *http.Request, headers []string) (string, string, error) {
	for _, headerName := range headers {
		raw := strings.TrimSpace(req.Header.Get(headerName))
		if len(raw) == 0 {
			continue
		}
		value := strings.TrimSpace(strings.Split(raw, ",")[0])
		if len(value) == 0 {
			continue
		}
		if strings.EqualFold(value, "null") || strings.EqualFold(value, "undefined") {
			return "", headerName, nil
		}
		host, err := hostFromOriginValue(value)
		if err != nil {
			return "", headerName, err
		}
		return host, headerName, nil
	}

	return "", "", nil
}

func hostFromOriginValue(value string) (string, error) {
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("invalid origin")
		}
		return normalizeHost(parsed.Host)
	}

	if strings.Contains(value, "/") {
		parsed, err := url.Parse("http://" + value)
		if err == nil && parsed.Host != "" {
			return normalizeHost(parsed.Host)
		}
	}

	return normalizeHost(value)
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	if len(host) == 0 {
		return "", fmt.Errorf("invalid origin")
	}
	if strings.Contains(host, ":") {
		if cleanHost, _, err := net.SplitHostPort(host); err == nil {
			host = cleanHost
		} else {
			host = strings.Split(host, ":")[0]
		}
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(host)
	if len(host) == 0 {
		return "", fmt.Errorf("invalid origin")
	}
	return host, nil
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

func (j *JWT) logDebug(format string, args ...interface{}) {
	if !j.shouldLog("debug") {
		return
	}
	if j.infoLogger == nil {
		j.infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	}
	j.infoLogger.Printf("DEBUG %s", fmt.Sprintf(format, args...))
}

func (j *JWT) logInfo(format string, args ...interface{}) {
	if !j.shouldLog("info") {
		return
	}
	if j.infoLogger == nil {
		j.infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	}
	j.infoLogger.Printf("INFO %s", fmt.Sprintf(format, args...))
}

func (j *JWT) logError(format string, args ...interface{}) {
	if !j.shouldLog("error") {
		return
	}
	if j.errorLogger == nil {
		j.errorLogger = log.New(os.Stderr, "", log.LstdFlags)
	}
	j.errorLogger.Printf("ERROR %s", fmt.Sprintf(format, args...))
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
