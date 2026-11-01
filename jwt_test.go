package traefik_jwt_introspector

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeToken(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".sig"
}

func TestLogsCallerWhenTokenHasNoEmail(t *testing.T) {
	active := true
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if active {
			w.Write([]byte(`{"active":true,"username":"svc-client","sub":"u-1","client_id":"account","contact_id":123456,"is_agent":true,"sid":"s-1"}`))
		} else {
			w.Write([]byte(`{"active":false}`))
		}
	}))
	defer keycloak.Close()

	cfg := CreateConfig()
	cfg.LogLevel = "info"
	cfg.Realms = []RealmConfig{{RealmName: "back-office", ClientID: "gateway", ClientSecret: "s", ValidateAPIUrl: keycloak.URL}}
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "t")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	handler.(*JWT).infoLogger = log.New(&out, "", 0)

	token := fakeToken(`{"iss":"https://auth/realms/back-office","preferred_username":"svc-client","azp":"account"}`)
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "https://api.example.com/v2/identity/contacts?page=7", nil)
		req.RemoteAddr = "203.0.113.7:50720"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "evil\nINFO event=token_active_email email=admin@x")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	send()
	line := out.String()
	for _, want := range []string{
		"event=token_active_no_email realm=back-office claims=introspection",
		"user=svc-client sub=u-1 client=account contact_id=123456 store_id=- is_agent=true sid=s-1",
		"peer=203.0.113.7 cf_ip=- method=GET host=api.example.com path=/v2/identity/contacts",
		`ua="evil\nINFO event=token_active_email email=admin@x"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("active log missing %q\n%s", want, line)
		}
	}
	if strings.Count(line, "\n") != 1 || strings.Contains(line, token) {
		t.Errorf("want one line without the token, got:\n%s", line)
	}

	out.Reset()
	active = false
	if rec := send(); rec.Code != http.StatusUnauthorized {
		t.Errorf("inactive token: got %d, want 401", rec.Code)
	}
	if want := "event=token_inactive_no_email realm=back-office claims=token user=svc-client sub=- client=account"; !strings.Contains(out.String(), want) {
		t.Errorf("inactive log missing %q\n%s", want, out.String())
	}
}

func TestDeniesTokensWithoutSessionUnlessServiceClient(t *testing.T) {
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"username":"service-account-svc","client_id":"svc","azp":"svc"}`))
	}))
	defer keycloak.Close()

	status := func(serviceClients ...string) int {
		cfg := CreateConfig()
		cfg.Realms = []RealmConfig{
			{RealmName: "back-office", ClientID: "gateway", ClientSecret: "s", ValidateAPIUrl: keycloak.URL, ServiceClients: serviceClients},
			{RealmName: "other", ClientID: "gateway", ClientSecret: "s", ValidateAPIUrl: keycloak.URL, ServiceClients: []string{"svc"}},
		}
		handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "t")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "https://api.example.com/v2/orders", nil)
		req.Header.Set("Authorization", "Bearer "+fakeToken(`{"iss":"https://auth/realms/back-office"}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := status(); got != http.StatusForbidden {
		t.Errorf("unlisted client without sid: got %d, want 403", got)
	}
	if got := status("other", "svc"); got != http.StatusOK {
		t.Errorf("listed client without sid: got %d, want 200", got)
	}
}
