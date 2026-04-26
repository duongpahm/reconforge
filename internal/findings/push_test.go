package findings

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/duongpahm/ReconForge/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleFinding() models.Finding {
	return models.Finding{
		FindingID:   "f1",
		Target:      "example.com",
		Severity:    "high",
		Type:        "url",
		Module:      "url_gf",
		Host:        "app.example.com",
		URL:         "https://app.example.com/login",
		Title:       "Sensitive endpoint",
		Description: "Potential secret exposure",
		RequestRaw:  "GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
	}
}

func TestNewBackendValidation(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	backend, err := newBackend("github", PushOptions{Repo: "org/repo"})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "GITHUB_TOKEN")

	t.Setenv("GITHUB_TOKEN", "gh-token")
	backend, err = newBackend("github", PushOptions{})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "--repo is required")

	t.Setenv("JIRA_TOKEN", "jira-token")
	backend, err = newBackend("jira", PushOptions{})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "--host and --project are required")

	t.Setenv("LINEAR_TOKEN", "linear-token")
	backend, err = newBackend("linear", PushOptions{})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "--team is required")

	backend, err = newBackend("unknown", PushOptions{})
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "unsupported ticket backend")
}

func TestDoJSONSuccessAndFailure(t *testing.T) {
	var authHeader, contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"html_url":"https://tickets.example/1"}`)
	}))
	defer server.Close()

	var out struct {
		HTMLURL string `json:"html_url"`
	}
	err := doJSON(context.Background(), server.Client(), http.MethodPost, server.URL, "token", map[string]string{"a": "b"}, &out)
	require.NoError(t, err)
	assert.Equal(t, "token", authHeader)
	assert.Equal(t, "application/json", contentType)
	assert.Equal(t, "https://tickets.example/1", out.HTMLURL)

	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer failServer.Close()

	err = doJSON(context.Background(), failServer.Client(), http.MethodPost, failServer.URL, "token", map[string]string{"a": "b"}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status")
}

func TestGitHubBackendPushUsesBearerAuth(t *testing.T) {
	var authHeader, acceptHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		acceptHeader = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.example/issue/1"})
	}))
	defer server.Close()

	backend := &GitHubBackend{
		token: "gh-token",
		repo:  "org/repo",
		client: &http.Client{
			Transport: rewriteTransport{baseURL: server.URL},
		},
	}

	url, err := backend.Push(context.Background(), sampleFinding())
	require.NoError(t, err)
	assert.Equal(t, "https://github.example/issue/1", url)
	assert.Equal(t, "Bearer gh-token", authHeader)
	assert.Equal(t, "application/vnd.github+json", acceptHeader)
}

func TestIssueBodyAndLabelsTitle(t *testing.T) {
	finding := sampleFinding()

	assert.Equal(t, "[HIGH] Sensitive endpoint", labelsTitle(finding))

	body := issueBody(finding)
	assert.Contains(t, body, "Target: example.com")
	assert.Contains(t, body, "Module: url_gf")
	assert.Contains(t, body, "Description:")
	assert.Contains(t, body, "```http")
}

type rewriteTransport struct {
	baseURL string
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := t.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header.Clone()
	return http.DefaultTransport.RoundTrip(newReq)
}

func TestLinearBackendPushFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"issueCreate":{"success":false,"issue":{"url":""}}}}`)
	}))
	defer server.Close()

	backend := &LinearBackend{
		token: "linear-token",
		team:  "TEAM",
		client: &http.Client{
			Transport: rewriteTransport{baseURL: server.URL},
		},
	}

	errURL, err := backend.Push(context.Background(), sampleFinding())
	require.Error(t, err)
	assert.Empty(t, errURL)
	assert.Contains(t, err.Error(), "success=false")
}

func TestJiraBackendPush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/rest/api/3/issue", r.URL.Path)
		assert.Equal(t, "jira-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"key":"SEC-123"}`)
	}))
	defer server.Close()

	backend := &JiraBackend{
		host:    server.URL,
		token:   "jira-token",
		project: "SEC",
		client:  server.Client(),
	}

	url, err := backend.Push(context.Background(), sampleFinding())
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(url, "/browse/SEC-123"))
}
