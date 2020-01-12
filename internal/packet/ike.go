package packet

type SPI []byte

// https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-21
type PayloadType byte

const (
	PayloadNone PayloadType = iota
	PayloadSecurityAssociation
	PayloadProposal
	PayloadTransform
	PayloadKeyExchange
	PayloadIdentification
	PayloadCertificate
	PayloadCertificateRequest
	PayloadHash
	PayloadSignature
	PayloadNonce
	PayloadNotification
	PayloadDelete
	PayloadVendorID
	PayloadReserved1
	PayloadSAKEK
	PayloadSATEK
	PayloadKeyDownload
	PayloadSequenceNumber
	PayloadProofOfPossession
	PayloadNATDiscovery
	PayloadNATOriginalAddress
	PayloadGroupAssociatedPolicy
	// 23-127 Unassigned
	// 128-255 Reserved for private use
)

// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2
type Payload2 byte

const (
	Payload2None Payload2 = 0
	// 1-33 reserved
	Payload2SA  = 33
	Payload2KE  = 34
	Payload2IDi = 35
	Payload2IDr = 36
	// ...
)

type IKEVersion byte

const (
	IKEVersion1 = 0x10
	IKEVersion2 = 0x20
)

type ExchangeType byte

const (
	// 0-33 Reserved
	ExchangeIKESAInit     = 34
	ExchangeIKEAuth       = 35
	ExchangeCreateChildSA = 36
	ExchangeInformational = 37
	// 38-239 Reserved to IANA
	// 240-255 Reserved for private use
)

type IkeSaInit struct {
	InitiatorSPI SPI
	ResponderSPI SPI
	NextPayload  PayloadType
	IKEVersion   IKEVersion
	ExchangeType ExchangeType
	Flags        byte
	MessageID    uint32
	Length       uint32
}
