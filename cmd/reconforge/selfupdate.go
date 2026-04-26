package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "embed"
	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
)

const (
	releaseRepo               = "duongpahm/ReconForge"
	releaseSigningFingerprint = "4C10 5CE2 18BD E48C 2267 0A2B B314 7C45 1DC4 8DAF"
)

//go:embed release-public-key.asc
var embeddedReleasePublicKey []byte

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

var selfUpdateYes bool

var selfUpdateCmd = &cobra.Command{
	Use:   "self-update",
	Short: "Update ReconForge from GitHub Releases",
	Example: strings.TrimSpace(`
  reconforge self-update
  reconforge self-update --yes
`),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Checking GitHub releases...")

		release, err := fetchLatestRelease(cmd.Context())
		if err != nil {
			return fmt.Errorf("check latest release: %w", err)
		}

		current := normalizeVersion(config.Version)
		latest := normalizeVersion(release.TagName)
		if latest == "" {
			return fmt.Errorf("latest release has empty tag")
		}
		if current != "" && !isNewerVersion(latest, current) {
			fmt.Printf("Already up to date (%s)\n", config.Version)
			return nil
		}

		fmt.Printf("New version: %s (current: %s)\n", release.TagName, config.Version)
		if !selfUpdateYes {
			ok, err := confirmUpdate(os.Stdin, os.Stdout)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("Update cancelled.")
				return nil
			}
		}

		binaryAsset, checksumAsset, signatureAsset := chooseReleaseAssets(release.Assets, runtime.GOOS, runtime.GOARCH)
		if binaryAsset == nil {
			return fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
		}

		fmt.Printf("Downloading %s...\n", binaryAsset.Name)
		payload, err := downloadAsset(cmd.Context(), binaryAsset.BrowserDownloadURL)
		if err != nil {
			return fmt.Errorf("download binary: %w", err)
		}

		binaryBytes, err := extractBinary(binaryAsset.Name, payload)
		if err != nil {
			return fmt.Errorf("extract binary: %w", err)
		}

		if checksumAsset != nil {
			sumPayload, err := downloadAsset(cmd.Context(), checksumAsset.BrowserDownloadURL)
			if err != nil {
				return fmt.Errorf("download checksum: %w", err)
			}
			if signatureAsset == nil {
				return fmt.Errorf("checksum signature asset not found")
			}
			sigPayload, err := downloadAsset(cmd.Context(), signatureAsset.BrowserDownloadURL)
			if err != nil {
				return fmt.Errorf("download checksum signature: %w", err)
			}
			pubKey, err := releasePublicKey()
			if err != nil {
				return fmt.Errorf("load release public key: %w", err)
			}
			if err := verifyReleaseSignature(sumPayload, sigPayload, pubKey); err != nil {
				return fmt.Errorf("verify checksum signature: %w", err)
			}
			fmt.Println("Verified checksum signature.")
			if err := verifyChecksum(binaryAsset.Name, binaryBytes, sumPayload); err != nil {
				return fmt.Errorf("verify checksum: %w", err)
			}
			fmt.Println("Verified checksum.")
		} else {
			fmt.Println("Checksum asset not found; skipping verification.")
		}

		exePath, err := os.Executable()
		if err != nil {
			return err
		}
		if err := replaceExecutable(exePath, binaryBytes); err != nil {
			return fmt.Errorf("replace binary: %w", err)
		}

		fmt.Println("Updated. Run 'reconforge version' to confirm.")
		return nil
	},
}

func fetchLatestRelease(ctx context.Context) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+releaseRepo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "reconforge-self-update")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("github api returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var release releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

func confirmUpdate(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprint(out, "Continue? [y/N] ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "refs/tags/")
	return strings.TrimPrefix(v, "v")
}

func isNewerVersion(candidate, current string) bool {
	cParts := parseVersionParts(candidate)
	curParts := parseVersionParts(current)
	maxLen := len(cParts)
	if len(curParts) > maxLen {
		maxLen = len(curParts)
	}
	for len(cParts) < maxLen {
		cParts = append(cParts, 0)
	}
	for len(curParts) < maxLen {
		curParts = append(curParts, 0)
	}
	for i := range cParts {
		if cParts[i] > curParts[i] {
			return true
		}
		if cParts[i] < curParts[i] {
			return false
		}
	}
	return false
}

func parseVersionParts(v string) []int {
	parts := strings.Split(normalizeVersion(v), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	return out
}

func chooseReleaseAssets(assets []releaseAsset, goos, goarch string) (*releaseAsset, *releaseAsset, *releaseAsset) {
	targets := expectedAssetNames(goos, goarch)
	var binary *releaseAsset
	var checksum *releaseAsset
	var signature *releaseAsset

	for i := range assets {
		name := assets[i].Name
		if checksum == nil && isChecksumAsset(name) {
			checksum = &assets[i]
			continue
		}
		if signature == nil && isChecksumSignatureAsset(name) {
			signature = &assets[i]
		}
		if binary != nil {
			continue
		}
		for _, target := range targets {
			if name == target || strings.HasSuffix(name, "/"+target) {
				binary = &assets[i]
				break
			}
		}
	}

	return binary, checksum, signature
}

func expectedAssetNames(goos, goarch string) []string {
	base := fmt.Sprintf("reconforge-%s-%s", goos, goarch)
	return []string{
		base + ".tar.gz",
		base + ".zip",
		base,
	}
}

func isChecksumAsset(name string) bool {
	lower := strings.ToLower(name)
	return !isChecksumSignatureAsset(name) && (strings.Contains(lower, "checksum") || strings.Contains(lower, "sha256"))
}

func isChecksumSignatureAsset(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "checksums.txt.sig") || strings.HasSuffix(lower, "checksum.txt.sig") || strings.HasSuffix(lower, ".sha256.sig")
}

func downloadAsset(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "reconforge-self-update")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func extractBinary(assetName string, payload []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(assetName, ".tar.gz"):
		return extractTarGz(payload)
	case strings.HasSuffix(assetName, ".zip"):
		return extractZip(payload)
	default:
		return payload, nil
	}
}

func extractTarGz(payload []byte) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(hdr.Name) == "reconforge" {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary not found in tar.gz archive")
}

func extractZip(payload []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(f.Name) != "reconforge" && filepath.Base(f.Name) != "reconforge.exe" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("binary not found in zip archive")
}

func verifyChecksum(assetName string, binary []byte, checksumPayload []byte) error {
	sum := sha256.Sum256(binary)
	want, err := checksumForAsset(assetName, checksumPayload)
	if err != nil {
		return err
	}
	if !bytes.Equal(sum[:], want) {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}

func releasePublicKey() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv("RECONFORGE_UPDATE_PUBLIC_KEY_FILE")); path != "" {
		return os.ReadFile(path)
	}
	if len(embeddedReleasePublicKey) == 0 {
		return nil, fmt.Errorf("embedded release public key is empty")
	}
	return embeddedReleasePublicKey, nil
}

func verifyReleaseSignature(message, sig, publicKey []byte) error {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKey))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	if bytes.HasPrefix(bytes.TrimSpace(sig), []byte("-----BEGIN PGP SIGNATURE-----")) {
		if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(sig)); err != nil {
			return err
		}
		return nil
	}

	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(sig)); err != nil {
		return err
	}
	return nil
}

func checksumForAsset(assetName string, payload []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		file := strings.TrimPrefix(fields[len(fields)-1], "*")
		if filepath.Base(file) != filepath.Base(assetName) {
			continue
		}
		raw := fields[0]
		sum, err := hex.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		return sum, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("checksum entry not found for %s", assetName)
}

func replaceExecutable(path string, binary []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "reconforge-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func init() {
	selfUpdateCmd.Flags().BoolVar(&selfUpdateYes, "yes", false, "Skip confirmation prompt")
	rootCmd.AddCommand(selfUpdateCmd)
}
