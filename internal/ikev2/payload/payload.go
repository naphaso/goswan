package payload

import (
	"errors"
)

type PayloadType byte

const (
	PayloadTypeNone   PayloadType = 0
	PayloadTypeSA                 = 33
	PayloadTypeKE                 = 34
	PayloadTypeNonce              = 40
	PayloadTypeNotify             = 41
)

const criticalFlag = uint8(0b10000000)
const noncriticalFlag = uint8(0)

type Payload interface {
	String() string
	AppendTo(b []byte) []byte
	ParseFrom(b []byte) error
}

type PayloadList []Payload

var ErrNoPayload = errors.New("cannot instantiate empty payload")
var ErrUnknownPayload = errors.New("unknown payload type")

func NewPayload(payloadType PayloadType) (Payload, error) {
	switch payloadType {
	case PayloadTypeNone:
		return nil, nil
	case PayloadTypeSA:
		return &PayloadSA{}, nil
	case PayloadTypeKE:
		return &PayloadKE{}, nil
	case PayloadTypeNonce:
		return &PayloadNonce{}, nil
	case PayloadTypeNotify:
		return &PayloadNotify{}, nil
	default:
		return nil, ErrUnknownPayload
	}
}

func GetFirstPayloadType(payloads []Payload) PayloadType {
	if len(payloads) == 0 {
		return PayloadTypeNone
	}
	return GetPayloadType(payloads[0])
}

func GetPayloadType(payload Payload) PayloadType {
	switch payload.(type) {
	case *PayloadSA:
		return PayloadTypeSA
	case *PayloadKE:
		return PayloadTypeKE
	case *PayloadNonce:
		return PayloadTypeNonce
	case *PayloadNotify:
		return PayloadTypeNotify
	default:
		return PayloadTypeNone
	}
}
