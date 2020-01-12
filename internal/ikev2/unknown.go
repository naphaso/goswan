package ikev2

import (
	"io"

	"github.com/naphaso/goswan/internal/ikev2/payload"
)

type UnknownPayload struct {
	PayloadType payload.PayloadType
	Critical    bool
	Data        []byte
}

func (s *UnknownPayload) WriteTo(r io.Writer) {

}
