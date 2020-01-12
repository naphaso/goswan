package payload

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
)

type NotifyType uint16

const (
	NotifyTypeNone NotifyType = 0

	NotifyInvalidKEPayload = 17

	NotifyNatDetectionSrcIP           = 16388
	NotifyNatDetectionDstIP           = 16389
	NotifyIKEv2FragmentationSupported = 16430
	NotifySignatureHashAlgorithms     = 16431
	NotifyRedirectSupported           = 16406
)

var _ Payload = &PayloadNotify{}

type PayloadNotify struct {
	Critical bool
	Type     NotifyType
	Data     []byte
}

func (s *PayloadNotify) AppendTo(buf []byte) []byte {
	buf = append(buf,
		0, // protocol id
		0, // spi size
		byte(uint16(s.Type)>>8), byte(uint16(s.Type)))
	if len(s.Data) > 0 {
		buf = append(buf, s.Data...)
	}
	return buf
}

func (s *PayloadNotify) ParseFrom(b []byte) error {
	s.Critical = (b[1] & criticalFlag) > 0
	if b[4] != 0 || b[5] != 0 {
		return fmt.Errorf("invalid notify payload. protocol_id and spi_size currently unsupported: %v", hex.EncodeToString(b[6:8]))
	}
	s.Type = NotifyType(uint16(b[7]) | uint16(b[6])<<8)
	if len(b) > 8 {
		s.Data = b[8:]
	}
	return nil
}

func (s *PayloadNotify) WriteTo(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, uint16(len(s.Data)+8))
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, uint8(0)) // protocol id
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, uint8(0)) // spi size
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, uint16(s.Type))
	if err != nil {
		return err
	}

	if len(s.Data) > 0 {
		_, err = w.Write(s.Data)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *PayloadNotify) ReadFrom(r io.Reader) error {
	var protocolId, spiSize uint8
	var notifyType uint16

	err := binary.Read(r, binary.BigEndian, &protocolId)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &spiSize)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &notifyType)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	s.Type = NotifyType(notifyType)
	s.Data = data
	return nil
}

func (s *PayloadNotify) String() string {
	if s.Type == NotifyInvalidKEPayload {
		if len(s.Data) != 2 {
			return "Notify{INVALID_KE_PAYLOAD,INVALID_DATA}"
		}

		transformID := uint16(s.Data[1]) | uint16(s.Data[0])<<8
		return fmt.Sprintf("Notify{INVALID_KE_PAYLOAD,DH_GROUP=%d}", transformID)
	}

	return "Notify{TBD}"
}
