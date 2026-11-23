package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBlockPageRecheck(t *testing.T) {
	s := NewAPIStub()

	rec := httptest.NewRecorder()
	s.handleBlockPageRecheck(rec, httptest.NewRequest(http.MethodPost, "/blockpage/recheck", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("no providers: status %d, want 404", rec.Code)
	}

	calls := 0
	s.SetBlockPageProviders(nil, nil, func() *BlockPageStatus {
		calls++
		return &BlockPageStatus{Active: true, Trusted: true}
	})

	rec = httptest.NewRecorder()
	s.handleBlockPageRecheck(rec, httptest.NewRequest(http.MethodGet, "/blockpage/recheck", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleBlockPageRecheck(rec, httptest.NewRequest(http.MethodPost, "/blockpage/recheck", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: status %d, want 200", rec.Code)
	}
	if calls != 1 {
		t.Errorf("recheck called %d times, want 1", calls)
	}
	var st BlockPageStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Active || !st.Trusted {
		t.Errorf("response = %+v, want the status recheck returned", st)
	}

	// Not in use any more.
	s.SetBlockPageProviders(nil, nil, func() *BlockPageStatus { return nil })
	rec = httptest.NewRecorder()
	s.handleBlockPageRecheck(rec, httptest.NewRequest(http.MethodPost, "/blockpage/recheck", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("nil status: status %d, want 404", rec.Code)
	}
}
