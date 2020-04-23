package exchange

// exchange types
// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
type Type byte

const (
	// 0-33 Reserved
	IKE_SA_INIT        Type = 34
	IKE_AUTH                = 35
	CREATE_CHILD_SA         = 36
	INFORMATIONAL           = 37
	IKE_SESSION_RESUME      = 38
	GSA_AUTH                = 39
	GSA_REGISTRATION        = 40
	GSA_REKEY               = 41
	// 42 Unassigned
	IKE_INTERMEDIATE = 43
	// 44-239 Unassigned
	// 240-255 Private use https://www.iana.org/go/rfc7296
)
