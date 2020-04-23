package payload

type PayloadUnknown struct {
	PayloadType PayloadType
	Critical    bool
	Data        []byte
}

func (s *PayloadUnknown) AppendTo(b []byte) []byte {
	return append(b, s.Data...)
}

func (s *PayloadUnknown) ParseFrom(b []byte) error {
	s.Critical = (b[1] & criticalFlag) > 0
	s.Data = b[4:]
	return nil
}

func (s *PayloadUnknown) String() string {
	return "UNKNOWN"
}
