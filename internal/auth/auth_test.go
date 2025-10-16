package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeySuccess(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey test")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("failed extracting API key: %s", err)
	}
	want := "test"

	if got != want {
		t.Fatalf("wrong key extracted - expected %s, got %s", want, got)
	}
}

func TestGetAPIKeyNoAuth(t *testing.T) {
	headers := make(http.Header)

	_, err := GetAPIKey(headers)
	if err != nil {
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Fatal("wrong error returned")
		}
	}
}

func TestGetAPIKeyWrongAuth(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "Basic test")

	_, err := GetAPIKey(headers)
	if err != nil {
		expected := "malformed authorization header"
		got := err.Error()
		if expected != got {
			t.Fatalf("wrong exception thrown, expected '%s', got '%s'", expected, got)
		}
	}
}
