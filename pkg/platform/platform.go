package platform

import (
	"errors"
	"fmt"

	"github.com/duongpahm/ReconForge/pkg/scope"
)

// PlatformClient defines the interface for bug bounty platforms.
type PlatformClient interface {
	GetScope(program string) (*scope.Scope, error)
}

// HackerOneClient implements PlatformClient for HackerOne.
type HackerOneClient struct {
	token string
}

func NewHackerOneClient(token string) *HackerOneClient {
	return &HackerOneClient{token: token}
}

func (c *HackerOneClient) GetScope(program string) (*scope.Scope, error) {
	if c.token == "" {
		return nil, errors.New("H1_TOKEN is required for HackerOne scope sync")
	}
	
	// TODO: In a real implementation, this would make HTTP requests to HackerOne's API
	// e.g. GET https://api.hackerone.com/v1/programs/{program}
	// For Sprint 7 parity, we return a mock scope to demonstrate the CLI workflow
	fmt.Printf("🔄 Fetching scope for %s from HackerOne (mocked)...\n", program)
	
	return &scope.Scope{
		InScope: []string{
			fmt.Sprintf("*.%s.com", program),
			fmt.Sprintf("api.%s.com", program),
		},
		OutOfScope: []string{
			fmt.Sprintf("blog.%s.com", program),
		},
	}, nil
}

// BugcrowdClient implements PlatformClient for Bugcrowd.
type BugcrowdClient struct {
	token string
}

func NewBugcrowdClient(token string) *BugcrowdClient {
	return &BugcrowdClient{token: token}
}

func (c *BugcrowdClient) GetScope(program string) (*scope.Scope, error) {
	if c.token == "" {
		return nil, errors.New("BUGCROWD_TOKEN is required for Bugcrowd scope sync")
	}
	
	// TODO: Real API call
	fmt.Printf("🔄 Fetching scope for %s from Bugcrowd (mocked)...\n", program)
	
	return &scope.Scope{
		InScope: []string{
			fmt.Sprintf("*.%s.net", program),
		},
		OutOfScope: []string{},
	}, nil
}

// GetClient returns the appropriate client based on platform name.
func GetClient(platformName, token string) (PlatformClient, error) {
	switch platformName {
	case "hackerone", "h1":
		return NewHackerOneClient(token), nil
	case "bugcrowd", "bc":
		return NewBugcrowdClient(token), nil
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platformName)
	}
}
