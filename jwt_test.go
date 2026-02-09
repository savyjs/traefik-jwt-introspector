package traefik_jwt_introspector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptionalAllowsMissingToken(t *testing.T) {
	t.Helper()

	var gotInjected string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotInjected = r.Header.Get("injectedPayload")
		w.WriteHeader(http.StatusOK)
	})

	cfg := &Config{
		Optional: true,
		HostRealmMap: map[string]string{
			"example.com": "realm-1",
		},
		Realms: []RealmConfig{
			{
				RealmName:      "realm-1",
				ClientID:       "client-1",
				ClientSecret:   "secret-1",
				ValidateAPIUrl: "http://example.com/introspect",
			},
		},
	}

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotInjected != "" {
		t.Fatalf("injectedPayload = %q, want empty", gotInjected)
	}
}

func TestRequiredBlocksMissingToken(t *testing.T) {
	t.Helper()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	cfg := &Config{
		Optional: false,
		HostRealmMap: map[string]string{
			"example.com": "realm-1",
		},
		Realms: []RealmConfig{
			{
				RealmName:      "realm-1",
				ClientID:       "client-1",
				ClientSecret:   "secret-1",
				ValidateAPIUrl: "http://example.com/introspect",
			},
		},
	}

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Fatalf("next handler should not be called")
	}
}

func TestHostRealmMappingUsesRealmCredentials(t *testing.T) {
	t.Helper()

	expectedToken := "abc123"
	expectedRealm := "back-office"
	expectedClientID := "client-1"
	expectedClientSecret := "secret-1"

	introspectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm error = %v", err)
		}
		realm, ok := realmFromPath(r.URL.Path)
		if !ok {
			t.Errorf("unexpected path = %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if realm != expectedRealm {
			t.Errorf("realm = %s, want %s", realm, expectedRealm)
		}
		if r.PostForm.Get("client_id") != expectedClientID {
			t.Errorf("client_id = %s, want %s", r.PostForm.Get("client_id"), expectedClientID)
		}
		if r.PostForm.Get("client_secret") != expectedClientSecret {
			t.Errorf("client_secret = %s, want %s", r.PostForm.Get("client_secret"), expectedClientSecret)
		}
		if r.PostForm.Get("token") != expectedToken {
			t.Errorf("token = %s, want %s", r.PostForm.Get("token"), expectedToken)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active":true,"realm":"`+realm+`"}`)
	}))
	defer introspectServer.Close()

	cfg := &Config{
		Optional:    false,
		BaseAuthURL: introspectServer.URL,
		HostRealmMap: map[string]string{
			"oobo.416-flowers.com": expectedRealm,
		},
		Realms: []RealmConfig{
			{
				RealmName:    expectedRealm,
				ClientID:     expectedClientID,
				ClientSecret: expectedClientSecret,
			},
		},
	}

	var gotInjected string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotInjected = r.Header.Get("injectedPayload")
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://oobo.416-flowers.com/resource", nil)
	req.Host = "oobo.416-flowers.com:8443"
	req.Header.Set("Authorization", "Bearer "+expectedToken)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotInjected == "" {
		t.Fatalf("injectedPayload should be set")
	}
}

func TestHostRealmMappingUnknownHost(t *testing.T) {
	t.Helper()

	cfg := &Config{
		Optional:    false,
		BaseAuthURL: "http://example.com",
		HostRealmMap: map[string]string{
			"oobo.416-flowers.com": "back-office",
		},
		Realms: []RealmConfig{
			{
				RealmName:    "back-office",
				ClientID:     "client-1",
				ClientSecret: "secret-1",
			},
		},
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/resource", nil)
	req.Host = "unknown.example.com"
	req.Header.Set("Authorization", "Bearer abc123")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Fatalf("next handler should not be called")
	}
}

func realmFromPath(path string) (string, bool) {
	trimmed := strings.Trim(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || parts[0] != "realms" {
		return "", false
	}
	return parts[1], true
}
