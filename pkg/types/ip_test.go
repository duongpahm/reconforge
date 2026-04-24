package types

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIP_Valid(t *testing.T) {
	tests := []struct {
		input string
		isV4  bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"::1", false},
		{"2001:db8::1", false},
		{"fe80::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip, err := NewIP(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.isV4, ip.IsV4())
			assert.Equal(t, !tt.isV4, ip.IsV6())
		})
	}
}

func TestNewIP_Invalid(t *testing.T) {
	tests := []string{
		"", "   ", "not-an-ip", "999.999.999.999",
		"192.168.1", "192.168.1.1.1",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := NewIP(input)
			assert.Error(t, err)
		})
	}
}

func TestIP_Properties(t *testing.T) {
	private, _ := NewIP("192.168.1.1")
	assert.True(t, private.IsPrivate())
	assert.False(t, private.IsLoopback())

	loopback, _ := NewIP("127.0.0.1")
	assert.True(t, loopback.IsLoopback())
}

func TestNewCIDR_Valid(t *testing.T) {
	tests := []struct {
		input     string
		prefix    int
		hostCount int64
	}{
		{"192.168.1.0/24", 24, 254},
		{"10.0.0.0/8", 8, 16777214},
		{"192.168.1.0/32", 32, 1},
		{"192.168.1.0/31", 31, 2},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cidr, err := NewCIDR(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.prefix, cidr.PrefixLen())
			assert.Equal(t, big.NewInt(tt.hostCount), cidr.HostCount())
		})
	}
}

func TestNewCIDR_Invalid(t *testing.T) {
	tests := []string{"", "not-a-cidr", "192.168.1.1", "192.168.1.0/33"}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := NewCIDR(input)
			assert.Error(t, err)
		})
	}
}

func TestCIDR_Contains(t *testing.T) {
	cidr, _ := NewCIDR("192.168.1.0/24")
	inside, _ := NewIP("192.168.1.100")
	outside, _ := NewIP("10.0.0.1")

	assert.True(t, cidr.Contains(inside))
	assert.False(t, cidr.Contains(outside))
}
