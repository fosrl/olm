package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnknownRouteReturnsUpgradeRequired(t *testing.T) {
	s := NewAPIStub()
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/future-endpoint", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != StatusAPIServiceOutdated {
		t.Fatalf("status = %d, want %d", rec.Code, StatusAPIServiceOutdated)
	}

	var body APIErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "api_route_unavailable" {
		t.Fatalf("error = %q, want api_route_unavailable", body.Error)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q, want application/json", rec.Header().Get("Content-Type"))
	}
}

func TestKnownRouteNotHandledByCatchAll(t *testing.T) {
	s := NewAPIStub()
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
