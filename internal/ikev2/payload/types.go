package payload

type Type byte

const (
	None    Type = 0
	SA           = 33
	KE           = 34
	IDi          = 35
	IDr          = 36
	CERT         = 37
	CERTREQ      = 38
	AUTH         = 39
)
