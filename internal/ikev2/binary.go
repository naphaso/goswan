package ikev2

import (
	"encoding/binary"
	"io"
)

const criticalFlag = uint8(0b10000000)
const noncriticalFlag = uint8(0)

func condByte(c bool, ifTrue byte, ifFalse byte) byte {
	if c {
		return ifTrue
	}
	return ifFalse
}

func write(w io.Writer, data interface{}) error {
	return binary.Write(w, binary.BigEndian, data)
}

func writev(w io.Writer, data ...interface{}) error {
	for _, v := range data {
		err := write(w, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func read(r io.Reader, data interface{}) error {
	return binary.Read(r, binary.BigEndian, data)
}

func readv(r io.Reader, data ...interface{}) error {
	for _, v := range data {
		err := read(r, v)
		if err != nil {
			return err
		}
	}
	return nil
}
