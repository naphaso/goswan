package ikev2

import (
	"errors"
	"io"

	"github.com/naphaso/goswan/internal/ikev2/exchange"

	"github.com/naphaso/goswan/internal/ikev2/payload"
)

type Packet struct {
	InitiatorSPI SPI
	ResponderSPI SPI
	Version      byte
	ExchangeType exchange.Type
	Flags        byte
	MessageID    uint32
	Payloads     payload.PayloadList
}

func (s *Packet) AppendTo(buf []byte) []byte {
	buf = append(buf, s.InitiatorSPI[:]...)
	buf = append(buf, s.ResponderSPI[:]...)
	buf = append(buf, byte(payload.GetFirstPayloadType(s.Payloads)))
	buf = append(buf, s.Version, byte(s.ExchangeType), s.Flags)
	buf = append(buf, byte(s.MessageID>>24), byte(s.MessageID>>16), byte(s.MessageID>>8), byte(s.MessageID))
	lengthOffset := len(buf)
	buf = append(buf, 0, 0, 0, 0) // length field
	for i := 0; i < len(s.Payloads); i++ {
		var nextPayload payload.PayloadType
		if i < len(s.Payloads)-1 {
			nextPayload = payload.GetPayloadType(s.Payloads[i+1])
		} else {
			nextPayload = payload.PayloadTypeNone
		}

		offset := len(buf)
		buf = append(buf, byte(nextPayload), 0, 0, 0) // next payload, non-critical flag and field for size
		buf = s.Payloads[i].AppendTo(buf)
		payloadSize := len(buf) - offset
		buf[offset+2] = byte(payloadSize >> 8)
		buf[offset+3] = byte(payloadSize)
	}
	l := len(buf)
	buf[lengthOffset] = byte(l >> 24)
	buf[lengthOffset+1] = byte(l >> 16)
	buf[lengthOffset+2] = byte(l >> 8)
	buf[lengthOffset+3] = byte(l)

	return buf
}

func (s *Packet) ParseFrom(buf []byte) error {
	if len(buf) < 28 {
		return io.ErrUnexpectedEOF
	}

	copy(s.InitiatorSPI[:], buf[:8])
	copy(s.ResponderSPI[:], buf[8:16])
	nextPayload := payload.PayloadType(buf[16])
	s.Version = buf[17]
	s.ExchangeType = exchange.Type(buf[18])
	s.Flags = buf[19]
	s.MessageID = uint32(buf[23]) | uint32(buf[22])<<8 | uint32(buf[21])<<16 | uint32(buf[20])<<24
	length := uint32(buf[27]) | uint32(buf[26])<<8 | uint32(buf[25])<<16 | uint32(buf[24])<<24
	if int(length) != len(buf) {
		return errors.New("invalid length")
	}

	buf = buf[28:]
	for nextPayload != payload.PayloadTypeNone {
		if len(buf) < 4 {
			return io.ErrUnexpectedEOF
		}

		p, err := payload.NewPayload(nextPayload)
		if err != nil {
			return err
		}

		nextPayload = payload.PayloadType(buf[0])
		//critical := buf[1]
		payloadLen := uint16(buf[3]) | uint16(buf[2])<<8
		if len(buf) < int(payloadLen) {
			return io.ErrUnexpectedEOF
		}

		err = p.ParseFrom(buf[:payloadLen])
		if err != nil {
			return err
		}
		s.Payloads = append(s.Payloads, p)
		buf = buf[payloadLen:]
	}

	if len(buf) > 0 {
		return errors.New("unknown additional bytes at the tail of the packet")
	}

	return nil
}
