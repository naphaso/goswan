package main

import (
	"encoding/hex"
	"log"
	"net"

	"github.com/naphaso/goswan/internal/ikev2/payload"

	"github.com/naphaso/goswan/internal/ikev2"
)

const (
	NextPayloadSA byte = 33
	NextPayloadKE      = 34

	IKEv2Version = 0x20

	IKE_SA_INIT = 34

	FlagInitiator       byte = 0b1000
	FlagNoHigherVersion      = 0b10000
	FlagRequest              = 0b100000

	CriticalBit    = 0b10000000
	NonCriticalBit = 0
)

func main() {
	packet := &ikev2.Packet{
		InitiatorSPI: ikev2.SPI{0xec, 0xd8, 0x3d, 0x2b, 0x7b, 0x74, 0x04, 0xe6},
		//InitiatorSPI: "\xec\xd8\x3d\x2b\x7b\x74\x04\xe6"),
		ResponderSPI: ikev2.SPI{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		//ResponderSPI: []byte("\x00\x00\x00\x00\x00\x00\x00\x00"),
		Version:      0x20,
		ExchangeType: ikev2.ExchangeTypeIKE_SA_INIT,
		Flags:        0x08, // initator
		MessageID:    0,
		Payloads: payload.PayloadList{
			&payload.PayloadSA{
				Proposals: []payload.Proposal{
					{
						Transforms: []payload.Transform{
							payload.ENCR_AES_CBC_128,
							payload.ENCR_AES_CBC_192,
							payload.ENCR_AES_CBC_256,
							payload.ENCR_AES_CTR_128,
							payload.ENCR_AES_CTR_192,
							payload.ENCR_AES_CTR_256,
							payload.ENCR_CAMELLIA_CBC_128,
							payload.ENCR_CAMELLIA_CBC_192,
							payload.ENCR_CAMELLIA_CBC_256,
							payload.ENCR_3DES,

							payload.INTEG_AUTH_HMAC_SHA2_256_128,
							payload.INTEG_AUTH_HMAC_SHA2_384_192,
							payload.INTEG_AUTH_HMAC_SHA2_512_256,
							payload.INTEG_AUTH_AES_XCBC_96,
							payload.INTEG_AUTH_AES_CMAC_96,
							payload.INTEG_AUTH_HMAC_SHA1_96,

							payload.PRF_AES_128_CBC,
							payload.PRF_AES_128_CMAC6,
							payload.PRF_HMAC_SHA2_256,
							payload.PRF_HMAC_SHA2_384,
							payload.PRF_HMAC_SHA2_512,
							payload.PRF_HMAC_SHA1,

							payload.DH_ECP_RANDOM_256,
							payload.DH_ECP_RANDOM_384,
							payload.DH_ECP_RANDOM_521,
							payload.DH_ECP_BRAINPOOL_256,
							payload.DH_ECP_BRAINPOOL_384,
							payload.DH_ECP_BRAINPOOL_512,
							payload.DH_CURVE25519,
							payload.DH_CURVE448,
							payload.DH_NTRU_128,
							payload.DH_NTRU_192,
							payload.DH_NTRU_256,
							payload.DH_NEWHOPE_128,
							payload.DH_MODP_3072,
							payload.DH_MODP_4096,
							payload.DH_MODP_6144,
							payload.DH_MODP_8192,
							payload.DH_MODP_2048,
						},
					},
					{
						Transforms: []payload.Transform{
							payload.ENCR_AES_CCM_16_128,
							payload.ENCR_AES_CCM_16_192,
							payload.ENCR_AES_CCM_16_256,
							payload.ENCR_AES_GCM_16_128,
							payload.ENCR_AES_GCM_16_192,
							payload.ENCR_AES_GCM_16_256,
							payload.ENCR_CHACHA20_POLY1305,
							payload.ENCR_AES_CCM_8_128,
							payload.ENCR_AES_CCM_8_192,
							payload.ENCR_AES_CCM_8_256,
							payload.ENCR_AES_CCM_12_128,
							payload.ENCR_AES_CCM_12_192,
							payload.ENCR_AES_CCM_12_256,
							payload.ENCR_AES_GCM_8_128,
							payload.ENCR_AES_GCM_8_192,
							payload.ENCR_AES_GCM_8_256,
							payload.ENCR_AES_GCM_12_128,
							payload.ENCR_AES_GCM_12_192,
							payload.ENCR_AES_GCM_12_256,

							payload.PRF_AES_128_CBC,
							payload.PRF_AES_128_CMAC6,
							payload.PRF_HMAC_SHA2_256,
							payload.PRF_HMAC_SHA2_384,
							payload.PRF_HMAC_SHA2_512,
							payload.PRF_HMAC_SHA1,

							payload.DH_ECP_RANDOM_256,
							payload.DH_ECP_RANDOM_384,
							payload.DH_ECP_RANDOM_521,
							payload.DH_ECP_BRAINPOOL_256,
							payload.DH_ECP_BRAINPOOL_384,
							payload.DH_ECP_BRAINPOOL_512,
							payload.DH_CURVE25519,
							payload.DH_CURVE448,
							payload.DH_NTRU_128,
							payload.DH_NTRU_192,
							payload.DH_NTRU_256,
							payload.DH_NEWHOPE_128,
							payload.DH_MODP_3072,
							payload.DH_MODP_4096,
							payload.DH_MODP_6144,
							payload.DH_MODP_8192,
							payload.DH_MODP_2048,
						},
					},
				},
			},
			&payload.PayloadKE{
				DHGroup: payload.ID_DH_ECP_RANDOM_256,
				Data: []byte("\x7a\x61\xfc\x17\x29\x95\xe3\x0c\x1a\xfb\xec\x94\x5c\x3e\x56\x3b" +
					"\x77\x9b\x12\x66\x25\xa1\xed\xbd\xfa\x0b\xeb\xc1\x51\x4d\x5f\x58" +
					"\x2b\x7c\x9b\x34\xbf\xe5\x9f\x0c\x4b\xd2\x01\x83\x35\x8e\xba\x71" +
					"\x53\x4d\x1b\x5f\xc6\x73\xda\xb5\xe9\x45\x1e\x12\xd9\x63\x37\xde"),
			},
			&payload.PayloadNonce{
				Data: []byte("\xf9\x64\x76\x4e\x84\x8d\xa6\x28\xfd\xe8\x1b\x57\x69\x7c\xd0\x5e" +
					"\x09\x61\x68\xa9\xb0\x30\xbb\x1c\x59\x93\xf5\x9d\x74\xfe\x60\xda"),
			},
			&payload.PayloadNotify{
				Type: payload.NotifyNatDetectionSrcIP,
				Data: []byte("\x4c\x48\xc1\x7d\x8a\x8c\xf6\x47\x6b\xb7\x1a\xd1\x56\xcc\x8a\x30" +
					"\x3e\x81\xb4\x1c"),
			},
			&payload.PayloadNotify{
				Type: payload.NotifyNatDetectionDstIP,
				Data: []byte("\x98\x68\xa7\x2c\x39\x51\x49\x4d\xcc\xc0\x19\x8a\xf7\x47\xe9\x8f" +
					"\xe0\xa7\x30\xa4"),
			},
			&payload.PayloadNotify{
				Type: payload.NotifyIKEv2FragmentationSupported,
			},
			&payload.PayloadNotify{
				Type: payload.NotifySignatureHashAlgorithms,
				Data: []byte("\x00\x02\x00\x03\x00\x04\x00\x05"),
			},
			&payload.PayloadNotify{
				Type: payload.NotifyRedirectSupported,
			},
		},
	}

	localAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:500")
	if err != nil {
		panic(err)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", "ipsec-server:500")
	if err != nil {
		panic(err)
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		panic(err)
	}

	var buffer []byte
	buffer = packet.AppendTo(buffer)
	if err != nil {
		panic(err)
	}
	_, err = conn.Write(buffer)
	if err != nil {
		panic(err)
	}
	for {
		var buf [1500]byte
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			panic(err)
		}

		log.Printf("packet from %s: %s", addr, hex.EncodeToString(buf[:n]))
		err = packet.ParseFrom(buf[:n])
		if err != nil {
			panic(err)
		}

		log.Printf("parsed packet: init_spi: %s, resp_spi: %s, version: %x, exchange type: %v, message_id: %d",
			packet.InitiatorSPI, packet.ResponderSPI,
			packet.Version,
			packet.ExchangeType,
			packet.MessageID)
	}

	_ = packet
}
