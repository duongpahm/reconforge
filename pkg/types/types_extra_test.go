package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Domain extra coverage ---

func TestDomain_Labels(t *testing.T) {
	d, err := NewDomain("sub.example.com")
	require.NoError(t, err)

	labels := d.Labels()
	assert.Equal(t, []string{"sub", "example", "com"}, labels)

	// Ensure returned slice is a copy (immutability)
	labels[0] = "modified"
	assert.Equal(t, "sub", d.Labels()[0])
}

func TestDomain_TLD_Root_Depth(t *testing.T) {
	d, err := NewDomain("deep.sub.example.com")
	require.NoError(t, err)
	assert.Equal(t, "com", d.TLD())
	assert.Equal(t, "example.com", d.Root())
	assert.Equal(t, 2, d.Depth())
}

func TestDomain_Depth_Root(t *testing.T) {
	d, err := NewDomain("example.com")
	require.NoError(t, err)
	assert.Equal(t, 0, d.Depth())
}

// --- IP extra coverage ---

func TestIP_String(t *testing.T) {
	ip, err := NewIP("192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip.String())
}

func TestIP_Net(t *testing.T) {
	ip, err := NewIP("10.0.0.1")
	require.NoError(t, err)
	assert.IsType(t, net.IP{}, ip.Net())
	assert.Equal(t, "10.0.0.1", ip.Net().String())
}

// --- CIDR extra coverage ---

func TestCIDR_String(t *testing.T) {
	cidr, err := NewCIDR("192.168.1.0/24")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", cidr.String())
}

func TestCIDR_Network(t *testing.T) {
	cidr, err := NewCIDR("10.0.0.0/8")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0", cidr.Network().String())
}

func TestCIDR_Mask(t *testing.T) {
	cidr, err := NewCIDR("192.168.1.0/24")
	require.NoError(t, err)
	ones, bits := cidr.Mask().Size()
	assert.Equal(t, 24, ones)
	assert.Equal(t, 32, bits)
}

func TestCIDR_IPNet(t *testing.T) {
	cidr, err := NewCIDR("172.16.0.0/12")
	require.NoError(t, err)
	ipNet := cidr.IPNet()
	assert.NotNil(t, ipNet)
	assert.IsType(t, &net.IPNet{}, ipNet)
}

// --- URL extra coverage ---

func TestURL_String(t *testing.T) {
	u, err := NewURL("https://example.com/path?q=1")
	require.NoError(t, err)
	assert.NotEmpty(t, u.String())
	assert.Contains(t, u.String(), "example.com")
}
