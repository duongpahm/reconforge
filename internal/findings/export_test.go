package findings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/duongpahm/ReconForge/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleFindings() []models.Finding {
	return []models.Finding{
		{
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
		},
		{
			FindingID:   "f2",
			Target:      "example.com",
			Severity:    "medium",
			Type:        "subdomain",
			Module:      "subfinder",
			Host:        "api.example.com:8443",
			Title:       "Interesting subdomain",
			Description: "Discovered via passive enumeration",
		},
	}
}

func TestWriteExport_NDJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, "ndjson", sampleFindings())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `"finding_id":"f1"`)
	assert.Contains(t, buf.String(), `"finding_id":"f2"`)
}

func TestWriteExport_CSV(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, "csv", sampleFindings())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "finding_id,target,severity")
	assert.Contains(t, buf.String(), "f1,example.com,high")
}

func TestWriteExport_NucleiTargets(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, "nuclei-targets", sampleFindings())
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Equal(t, []string{"api.example.com:8443", "app.example.com"}, lines)
}

func TestWriteExport_BurpXML(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, "burp-xml", sampleFindings())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "<issues")
	assert.Contains(t, buf.String(), "<name>Sensitive endpoint</name>")
	assert.Contains(t, buf.String(), "<severity>high</severity>")
}

func TestWriteExport_MarkdownAndPlatformFormats(t *testing.T) {
	t.Run("markdown", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteExport(&buf, "markdown", sampleFindings())
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "# Findings Export")
		assert.Contains(t, buf.String(), "## Details")
		assert.Contains(t, buf.String(), "Sensitive endpoint")
	})

	t.Run("hackerone", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteExport(&buf, "hackerone", sampleFindings())
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "HackerOne Submission Draft")
		assert.Contains(t, buf.String(), "### Reproduction")
	})

	t.Run("bugcrowd", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteExport(&buf, "bugcrowd", sampleFindings())
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "Bugcrowd Submission Draft")
	})
}

func TestWriteExport_UnsupportedFormat(t *testing.T) {
	var buf bytes.Buffer
	err := WriteExport(&buf, "nope", sampleFindings())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported findings export format")
}

func TestWriteOutput_FileAndStdout(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "nested", "findings.md")
	require.NoError(t, writeOutput(outFile, []byte("hello")))

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}

func TestMarshalFindingJSONAndHelpers(t *testing.T) {
	finding := sampleFindings()[0]

	data, err := MarshalFindingJSON(finding)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"finding_id":"f1"`)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "high", decoded["severity"])

	assert.Equal(t, "app.example.com", bestHost(finding))
	assert.Equal(t, "app.example.com", findingNucleiTarget(finding))
	assert.Equal(t, "fallback", defaultValue("", "fallback"))
	assert.Equal(t, "a\\|b", escapePipes("a|b"))
	assert.Equal(t, "&lt;tag&gt;", xmlEscape("<tag>"))
}

func TestBestHostAndBestTitleFallbacks(t *testing.T) {
	finding := models.Finding{
		FindingID:   "fid",
		URL:         "https://api.example.com:8443/path",
		Description: "desc",
	}

	assert.Equal(t, "api.example.com:8443", bestHost(finding))
	assert.Equal(t, "desc", bestTitle(finding))
	assert.Equal(t, "", bestHost(models.Finding{URL: "::://bad"}))
	assert.Equal(t, "fid", bestTitle(models.Finding{FindingID: "fid"}))
}
