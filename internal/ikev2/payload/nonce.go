package payload

import (
	"encoding/binary"
	"io"
	"io/ioutil"
)

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

func (s *PayloadNonce) WriteTo(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, uint16(len(s.Data)+4))
	if err != nil {
		return err
	}

	_, err = w.Write(s.Data)
	if err != nil {
		return err
	}

	return nil
	//return ikev2.writev(w,
	//	//byte(nextPayload),
	//	//condByte(s.Critical, criticalFlag, noncriticalFlag),
	//	uint16(len(s.Data)+4),
	//	s.Data)
}

func (s *PayloadNonce) ReadFrom(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	s.Data = data
	return nil
}

func (s *PayloadNonce) String() string {
	return "NONCE{TBD}"
}
