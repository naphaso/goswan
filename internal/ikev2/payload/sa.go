package payload

import (
	"errors"
	"io"
)

var _ Payload = &PayloadSA{}

type PayloadSA struct {
	Critical  bool
	Proposals []Proposal
}

type Proposal struct {
	Critical   bool
	Transforms []Transform
}

func (s *PayloadSA) AppendTo(buf []byte) []byte {

	for i, p := range s.Proposals {
		if i == len(s.Proposals)-1 {
			buf = append(buf, 0)
		} else {
			buf = append(buf, 2)
		}

		if s.Critical {
			buf = append(buf, criticalFlag)
		} else {
			buf = append(buf, noncriticalFlag)
		}

		offset := len(buf)
		buf = append(buf,
			0, 0, // reserved to transforms length
			byte(i+1), // number of current proposal
			1, 0,      // something
			byte(len(p.Transforms)),
		)

		for j, t := range p.Transforms {
			if j == len(p.Transforms)-1 {
				buf = append(buf, 0)
			} else {
				buf = append(buf, 3)
			}

			if t.Critical {
				buf = append(buf, criticalFlag)
			} else {
				buf = append(buf, noncriticalFlag)
			}

			if t.KeyLength == 0 {
				buf = append(buf, 0, 8)
			} else {
				buf = append(buf, 0, 12)
			}

			buf = append(buf, byte(t.Type), 0, byte(uint16(t.TransformID)>>8), byte(uint16(t.TransformID)))

			if t.KeyLength != 0 {
				buf = append(buf, 0x80, 0x0E, byte(t.KeyLength>>8), byte(t.KeyLength))
			}
		}

		l := len(buf) - offset + 2
		buf[offset] = byte(l >> 8)
		buf[offset+1] = byte(l)
	}

	return buf
}

func (s *PayloadSA) ParseFrom(b []byte) error {
	// 1 byte next payload
	// 2 byte critical flag
	// 3-4 bytes length field, already parsed
	// next 8 bytes is a header of mandatory first proposal
	if len(b) < 12 {
		return io.ErrUnexpectedEOF
	}

	s.Critical = (b[2] & criticalFlag) > 0
	b = b[4:]
	last := false
	var pnum byte = 1
	for !last && len(b) > 7 {
		switch b[0] {
		case 0:
			last = true
		case 2:
			last = false
		default:
			return errors.New("invalid next proposal field value")
		}

		var p Proposal
		p.Critical = (b[1] & criticalFlag) > 0
		plen := uint16(b[3]) | uint16(b[2])<<8
		if len(b) < int(plen) {
			return errors.New("invalid proposal len")
		}

		if pnum != b[4] {
			return errors.New("invalid proposal num")
		}
		pnum += 1

		// b[5], b[6] something
		tnum := b[7] // transform count
		b = b[8:]
		tlast := false
		for !tlast && tnum > 0 && len(b) > 7 {
			var t Transform
			switch b[0] {
			case 0:
				tlast = true
			case 3:
				tlast = false
			default:
				return errors.New("invalid next transform field value")
			}

			t.Critical = (b[1] & criticalFlag) > 0
			if b[2] != 0 {
				return errors.New("invalid transform len field, second byte")
			}
			tlen := b[3]
			if tlen != 8 && tlen != 12 {
				return errors.New("invalid transform len field, first byte")
			}

			if len(b) < int(tlen) {
				return io.ErrUnexpectedEOF
			}

			t.Type = TransformType(b[4])
			if b[5] != 0 {
				// TODO: add comment about this field
				return errors.New("invalid something")
			}
			t.TransformID = TransformID(uint16(b[7]) | uint16(b[6])<<8)

			if tlen == 12 {
				if b[8] != 0x80 || b[9] != 0x0E { // field type: key length
					return errors.New("invalid trasform field type")
				}

				t.KeyLength = uint16(b[11]) | uint16(b[10])<<8
			}

			tnum--
			b = b[tlen:]

			p.Transforms = append(p.Transforms, t)
		}
		if !tlast || tnum > 0 {
			return errors.New("invalid trasform list borders")
		}

		s.Proposals = append(s.Proposals, p)
	}

	if !last || len(b) > 0 {
		return errors.New("invalid proposal list borders")
	}

	return nil
}

func (s *PayloadSA) String() string {
	return "SA{TBD}"
}
