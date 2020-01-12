package payload

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func BenchmarkBinaryWrite(b *testing.B) {
	var v uint16
	var w bytes.Buffer
	for n := 0; n < b.N; n++ {
		binary.Write(&w, binary.BigEndian, v)
		v++
		w.Reset()
	}
}

func BenchmarkManualWrite(b *testing.B) {
	var v uint16
	var w bytes.Buffer
	for n := 0; n < b.N; n++ {
		var buf [2]byte
		bufs := buf[:]
		binary.BigEndian.PutUint16(bufs, v)
		w.Write(bufs)
		v++
		w.Reset()
	}
}

func BenchmarkRawWrite(b *testing.B) {
	var v uint16
	var w bytes.Buffer
	for n := 0; n < b.N; n++ {
		w.WriteByte(byte(v >> 8))
		w.WriteByte(byte(v))
		v++
		w.Reset()
	}
}

func BenchmarkArray(b *testing.B) {
	var buf [1500]byte
	slice := buf[:]
	var v uint16
	for n := 0; n < b.N; n++ {
		slice[0] = byte(v >> 8)
		slice[1] = byte(v)
		v++
		slice = slice[2:]
		slice = buf[:]
	}
}

func BenchmarkAppend(b *testing.B) {
	buf := make([]byte, 0, 1000)
	sbuf := buf
	var v uint16
	for n := 0; n < b.N; n++ {
		sbuf = append(sbuf, byte(v>>8), byte(v))
		v++
		sbuf = buf
	}
}

func BenchmarkAppendSeparate(b *testing.B) {
	buf := make([]byte, 0, 1000)
	sbuf := buf
	for n := 0; n < b.N; n++ {
		sbuf = append(sbuf, 1)
		sbuf = append(sbuf, 2)
		sbuf = append(sbuf, 3)
		sbuf = append(sbuf, 4)
		sbuf = append(sbuf, 5)
		sbuf = append(sbuf, 6)
		sbuf = append(sbuf, 7)
		sbuf = append(sbuf, 8)
		sbuf = append(sbuf, 9)
		sbuf = buf
	}
}

func BenchmarkAppendCombined(b *testing.B) {
	buf := make([]byte, 0, 1000)
	sbuf := buf
	for n := 0; n < b.N; n++ {
		sbuf = append(sbuf, 1, 2, 3, 4, 5, 6, 7, 8, 9)
		sbuf = buf
	}
}
