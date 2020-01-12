package payload

import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

var _ Payload = &PayloadKE{}

type PayloadKE struct {
	Critical bool
	DHGroup  TransformID
	Data     []byte
}

func (s *PayloadKE) AppendTo(buf []byte) []byte {
	buf = append(buf, byte(uint16(s.DHGroup)>>8), byte(uint16(s.DHGroup)), 0, 0)
	buf = append(buf, s.Data...)
	return buf
}

func (s *PayloadKE) ParseFrom(b []byte) error {
	s.Critical = (b[1] & criticalFlag) > 0
	s.DHGroup = TransformID(uint16(b[5]) | uint16(b[4])<<8)
	if b[6] != 0 || b[7] != 0 {
		return errors.New("invalid ke payload. protocol_id and spi_size currently unsupported")
	}
	s.Data = b[8:]
	return nil
}

func (s *PayloadKE) WriteTo(w io.Writer) error {
	_ = binary.Write(w, binary.BigEndian, uint16(len(s.Data)+8))
	_ = binary.Write(w, binary.BigEndian, uint16(s.DHGroup))
	_ = binary.Write(w, binary.BigEndian, uint16(0))

	if len(s.Data) > 0 {
		_, _ = w.Write(s.Data)
	}

	return nil
}

func (s *PayloadKE) ReadFrom(r io.Reader) error {
	var dhGroup uint16
	err := binary.Read(r, binary.BigEndian, &dhGroup)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	s.DHGroup = TransformID(dhGroup)
	s.Data = data
	return nil
}

func (s *PayloadKE) String() string {
	return "KE{TBD}"
}
