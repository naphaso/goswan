package ikev2

import (
	"encoding/hex"
	"fmt"
)

type SPI [8]byte

func (s SPI) String() string {
	return hex.EncodeToString(s[:])
}

func SPIFromHex(v string) (SPI, error) {
	var spi SPI

	data, err := hex.DecodeString(v)
	if err != nil {
		return spi, fmt.Errorf("invalid hex SPI: %w", err)
	}

	if len(data) != 8 {
		return spi, fmt.Errorf("invalid hex SPI length: %v", v)
	}

	copy(spi[:], data)
	return spi, nil
}

func MustSPIFromHex(v string) SPI {
	spi, err := SPIFromHex(v)
	if err != nil {
		panic(err)
	}

	return spi
}
