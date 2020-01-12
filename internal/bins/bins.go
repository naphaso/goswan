package bins

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
)

func New() *Writer {
	var b bytes.Buffer
	return &Writer{
		w: &b,
		b: &b,
	}
}

type Writer struct {
	t [8]byte
	w io.Writer
	b *bytes.Buffer
}

func (s *Writer) WriteByte(v byte) {
	s.t[0] = v
	_, _ = s.w.Write(s.t[:1])
}

func (s *Writer) WriteUint16(v uint16) {
	a := s.t[:2]
	binary.BigEndian.PutUint16(a, v)
	_, _ = s.w.Write(a)
}

func (s *Writer) WriteUint32(v uint32) {
	a := s.t[:4]
	binary.BigEndian.PutUint32(a, v)
	_, _ = s.w.Write(a)
}

func (s *Writer) WriteBytes(v []byte) {
	_, _ = s.w.Write(v)
}

func (s *Writer) Bytes() []byte {
	return s.b.Bytes()
}

func (s *Writer) String() string {
	return hex.EncodeToString(s.b.Bytes())
}
