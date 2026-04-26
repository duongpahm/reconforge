package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNewerVersion(t *testing.T) {
	assert.True(t, isNewerVersion("v0.5.0", "v0.4.2"))
	assert.False(t, isNewerVersion("v0.4.2", "v0.5.0"))
	assert.False(t, isNewerVersion("v0.5.0", "v0.5.0"))
}

func TestChooseReleaseAssets(t *testing.T) {
	assets := []releaseAsset{
		{Name: "checksums.txt"},
		{Name: "reconforge-darwin-arm64.tar.gz"},
		{Name: "reconforge-linux-amd64.tar.gz"},
	}
	bin, sum := chooseReleaseAssets(assets, "darwin", "arm64")
	require.NotNil(t, bin)
	require.NotNil(t, sum)
	assert.Equal(t, "reconforge-darwin-arm64.tar.gz", bin.Name)
	assert.Equal(t, "checksums.txt", sum.Name)
}

func TestChecksumForAsset(t *testing.T) {
	data := []byte("binary")
	sum := sha256.Sum256(data)
	payload := []byte(hex.EncodeToString(sum[:]) + "  reconforge-darwin-arm64.tar.gz\n")
	got, err := checksumForAsset("reconforge-darwin-arm64.tar.gz", payload)
	require.NoError(t, err)
	assert.Equal(t, sum[:], got)
}

func TestExtractTarGz(t *testing.T) {
	var tarBuf bytes.Buffer
	gzw := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gzw)
	content := []byte("hello")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "reconforge",
		Mode: 0o755,
		Size: int64(len(content)),
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gzw.Close())

	out, err := extractTarGz(tarBuf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, content, out)
}
