package runner

import "os"

// SetProxyEnv sets proxy environment variables for child process inheritance.
func SetProxyEnv(proxyURL string) {
	if proxyURL == "" {
		return
	}

	_ = os.Setenv("HTTP_PROXY", proxyURL)
	_ = os.Setenv("HTTPS_PROXY", proxyURL)
	_ = os.Setenv("http_proxy", proxyURL)
	_ = os.Setenv("https_proxy", proxyURL)
}
