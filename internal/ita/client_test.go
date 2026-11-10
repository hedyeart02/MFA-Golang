package ita

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestParseITAUsersJSON_Array(t *testing.T) {
	rawJSON := `[
		{
			"username": "apc",
			"email": "apc@schneider.com",
			"fullName": "Administrator"
		},
		{
			"userName": "itaadmin",
			"emailAddress": "itaadmin@samlguard.local",
			"displayName": "ITA Admin"
		}
	]`

	users, err := ParseITAUsersJSON([]byte(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	if users[0].Username != "apc" || users[0].Email != "apc@schneider.com" {
		t.Errorf("unexpected user 0: %+v", users[0])
	}
	if users[1].Username != "itaadmin" || users[1].Email != "itaadmin@samlguard.local" {
		t.Errorf("unexpected user 1: %+v", users[1])
	}
}

func TestParseITAUsersJSON_ObjectWithData(t *testing.T) {
	rawJSON := `{
		"data": [
			{
				"id": "operator1",
				"email": "operator1@company.com",
				"name": "Operator One"
			}
		]
	}`

	users, err := ParseITAUsersJSON([]byte(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "operator1" {
		t.Errorf("expected operator1, got %s", users[0].Username)
	}
}

func TestFetchUsers_MockTransport(t *testing.T) {
	mockClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) *http.Response {
			if r.URL.Path == "/api/current/users" {
				auth := r.Header.Get("Authorization")
				if auth == "" {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
						Header:     make(http.Header),
					}
				}
				jsonResp := `[{"username": "apc", "email": "apc@company.com", "fullName": "Admin"}]`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(jsonResp)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "not found"}`)),
				Header:     make(http.Header),
			}
		}),
	}

	client := &Client{httpClient: mockClient}
	users, err := client.FetchUsers(context.Background(), "https://192.168.0.119/api/current", "apc", "password123")
	if err != nil {
		t.Fatalf("FetchUsers failed: %v", err)
	}
	if len(users) != 1 || users[0].Username != "apc" {
		t.Fatalf("unexpected users: %+v", users)
	}
}
