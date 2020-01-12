package ikev2

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
)

func calcNatHash(ispi, rspi SPI, addr *net.UDPAddr) []byte {
	hash := sha1.New()
	hash.Write(ispi[:])
	hash.Write(rspi[:])
	hash.Write(addr.IP.To4())
	var port [2]byte
	port[0] = byte(uint16(addr.Port) >> 8)
	port[1] = byte(uint16(addr.Port))
	hash.Write(port[:])
	return hash.Sum(nil)
}

func bruteforceInternalAddressFromHash(ispi, rspi SPI, hash []byte) (string, error) {
	networks := []string{
		"10.0.0.0/8",
		"192.168.0.0/16",
	}
	for _, network := range networks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			return "", err
		}

		var ipbytes = [4]byte{}
		ip := net.IP(ipbytes[:])
		addr := &net.UDPAddr{
			IP:   ip,
			Port: 500,
		}

		subnetStart := binary.BigEndian.Uint32(ipnet.IP.To4())
		ones, bites := ipnet.Mask.Size()
		subnetStop := subnetStart + uint32(1<<(bites-ones))
		subnetCurr := subnetStart

		for subnetCurr < subnetStop {
			binary.BigEndian.PutUint32(ip, subnetCurr)
			if bytes.Equal(calcNatHash(ispi, rspi, addr), hash) {
				return addr.String(), nil
			}
			subnetCurr++
		}
	}

	return "", errors.New("not found")
}
