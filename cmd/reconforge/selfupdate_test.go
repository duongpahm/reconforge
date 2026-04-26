package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	packet "golang.org/x/crypto/openpgp/packet"
)

func TestIsNewerVersion(t *testing.T) {
	assert.True(t, isNewerVersion("v0.5.0", "v0.4.2"))
	assert.False(t, isNewerVersion("v0.4.2", "v0.5.0"))
	assert.False(t, isNewerVersion("v0.5.0", "v0.5.0"))
}

func TestChooseReleaseAssets(t *testing.T) {
	assets := []releaseAsset{
		{Name: "checksums.txt"},
		{Name: "checksums.txt.sig"},
		{Name: "reconforge-darwin-arm64.tar.gz"},
		{Name: "reconforge-linux-amd64.tar.gz"},
	}
	bin, sum, sig := chooseReleaseAssets(assets, "darwin", "arm64")
	require.NotNil(t, bin)
	require.NotNil(t, sum)
	require.NotNil(t, sig)
	assert.Equal(t, "reconforge-darwin-arm64.tar.gz", bin.Name)
	assert.Equal(t, "checksums.txt", sum.Name)
	assert.Equal(t, "checksums.txt.sig", sig.Name)
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

func TestVerifyReleaseSignature(t *testing.T) {
	publicKey, message, signature := generateSignatureFixture(t)
	require.NoError(t, verifyReleaseSignature(message, signature, publicKey))
}

func TestVerifyReleaseSignature_Invalid(t *testing.T) {
	publicKey, message, signature := generateSignatureFixture(t)
	signature[len(signature)-1] ^= 0xFF
	err := verifyReleaseSignature(message, signature, publicKey)
	require.Error(t, err)
}

func TestVerifyReleaseSignature_MissingSig(t *testing.T) {
	publicKey, message, _ := generateSignatureFixture(t)
	err := verifyReleaseSignature(message, nil, publicKey)
	require.Error(t, err)
}

func generateSignatureFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	cfg := &packet.Config{
		RSABits:     2048,
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return time.Unix(0, 0) },
	}
	entity, err := openpgp.NewEntity("ReconForge Test", "unit test", "test@example.com", cfg)
	require.NoError(t, err)

	var publicKey bytes.Buffer
	pubWriter, err := armor.Encode(&publicKey, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.Serialize(pubWriter))
	require.NoError(t, pubWriter.Close())

	message := []byte("checksums.txt content\n")
	var signature bytes.Buffer
	require.NoError(t, openpgp.DetachSign(&signature, entity, bytes.NewReader(message), nil))

	_ = rand.Reader
	return publicKey.Bytes(), message, signature.Bytes()
}
