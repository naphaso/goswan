package payload

type Type byte

// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
const (
	None Type = 0
	// 1-32 Reserved
	SA      = 33 // Security Association
	KE      = 34 // Key Exchange
	IDi     = 35 // Identification - Initiator
	IDr     = 36 // Identification - Responder
	CERT    = 37 // Certificate
	CERTREQ = 38 // Certificate Request
	AUTH    = 39 // Authentication
	Nonce   = 40 // Nonce, Ni, Nr
	Notify  = 41 // Notify
	Delete  = 42
)
