package web

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/duongpahm/ReconForge/internal/module"
)

// RegisterAll registers all web modules with the given registry.
func RegisterAll(registry *module.Registry) {
	registry.Register(&HTTPXProbe{})
	registry.Register(&Screenshots{})
	registry.Register(&Crawler{})
	registry.Register(&JSAnalyzer{})
	registry.Register(&WAFDetector{})
	registry.Register(&ParamDiscovery{})
	registry.Register(&PortScan{})
	registry.Register(&CDNProvider{})
	registry.Register(&VirtualHosts{})
	registry.Register(&WebFuzz{})
	registry.Register(&URLChecks{})
	registry.Register(&URLGF{})
	registry.Register(&URLExt{})
	registry.Register(&CMSScanner{})
	registry.Register(&ServiceFingerprint{})
	registry.Register(&NucleiCheck{})
	registry.Register(&GraphQLScan{})
	registry.Register(&IISShortname{})
	registry.Register(&TLSIPPivots{})
	registry.Register(&FavireconTech{})
	registry.Register(&JSChecks{})
	registry.Register(&BrokenLinks{})
	registry.Register(&WordlistGen{})
	registry.Register(&SubJSExtract{})
	registry.Register(&WellKnownPivots{})
	registry.Register(&GrpcReflection{})
	registry.Register(&WebsocketChecks{})
	registry.Register(&WordlistGenRoboxtractor{})
	registry.Register(&PasswordDict{})
	registry.Register(&LLMProbe{})
}

// --- Helpers (shared with web package) ---

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func parseLines(data []byte) []string {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
