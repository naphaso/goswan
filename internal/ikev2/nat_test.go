package ikev2

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNatHash(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "10.0.1.69:500")
	require.NoError(t, err)
	ispi := SPI{0x5d, 0xd3, 0xcc, 0xc0, 0x75, 0xaf, 0x7c, 0x4b}
	rspi := SPI{0, 0, 0, 0, 0, 0, 0, 0}
	hash := calcNatHash(ispi, rspi, addr)
	require.Equal(t, "f6865a8c298e63ddefcf7daa5a3f81ff14601b5d", hex.EncodeToString(hash))
}

func TestNatBruteforce(t *testing.T) {
	ispi := SPI{0x5d, 0xd3, 0xcc, 0xc0, 0x75, 0xaf, 0x7c, 0x4b}
	rspi := SPI{0, 0, 0, 0, 0, 0, 0, 0}
	hash, err := hex.DecodeString("f6865a8c298e63ddefcf7daa5a3f81ff14601b5d")
	require.NoError(t, err)

	addr, err := bruteforceInternalAddressFromHash(ispi, rspi, hash)
	require.NoError(t, err)
	require.Equal(t, "10.0.1.69:500", addr)
}
