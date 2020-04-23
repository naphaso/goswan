package payload

var _ Payload = &PayloadNonce{}

type PayloadNonce struct {
	Critical bool
	Data     []byte
}

func (s *PayloadNonce) AppendTo(buf []byte) []byte {
	return append(buf, s.Data...)
}

func (s *PayloadNonce) ParseFrom(b []byte) error {
	s.Critical = (b[1] & criticalFlag) > 0
	s.Data = b[4:]
	return nil
}

func (s *PayloadNonce) String() string {
	return "NONCE{TBD}"
}
