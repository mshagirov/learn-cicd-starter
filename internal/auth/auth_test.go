package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testKey := "123-test_user_token-890"
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Errorf("Error creating a new request: %v", err)
	}
	req.Header.Add("Authorization", "ApiKey "+testKey)
	apiKey, err := GetAPIKey(req.Header)
	if err != nil {
		t.Errorf("Couldn't get ApiKey: %v", err)
	}
	if apiKey != testKey {
		t.Errorf("ApiKey didn't match target:\n\twanted: %v\n\tgot:%v", testKey, apiKey)
	}
}

func TestGetAPIKeyWrongKey(t *testing.T) {
	testKey := "123-test_user_token-"
	wrongKey := testKey + "890"
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Errorf("Error creating a new request: %v", err)
	}
	req.Header.Add("Authorization", "ApiKey "+wrongKey)
	apiKey, err := GetAPIKey(req.Header)
	if err != nil {
		t.Errorf("Couldn't get ApiKey: %v", err)
	}
	if apiKey == testKey {
		t.Errorf("ApiKey should NOT match target:\n\twanted: %v\n\tgot:%v", wrongKey, apiKey)
	}
}

func TestGetApiKeyNoKey(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Errorf("net/http error: %v", err)
	}
	req.Header.Add("Authorization", "Token some_token_123")
	if _, err := GetAPIKey(req.Header); err == nil {
		t.Errorf("Expected 'malformed key...' error got nil")
	}
}
