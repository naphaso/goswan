package dh

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

type DH interface {
	Generate() (privKey, pubKey []byte, err error)
	MakeSecret(privKey, pubKey []byte) ([]byte, error)
}

type ECP struct{ elliptic.Curve }

var ECP224 = ECP{elliptic.P224()}
var ECP256 = ECP{elliptic.P256()}
var ECP384 = ECP{elliptic.P384()}
var ECP521 = ECP{elliptic.P521()}

func (s ECP) Generate() (privkey, pubkey []byte, err error) {
	var x, y *big.Int
	privkey, x, y, err = elliptic.GenerateKey(s, rand.Reader)
	if err != nil {
		return
	}

	byteLen := (s.Params().BitSize + 7) >> 3
	pubkey = make([]byte, 2*byteLen)
	xBytes := x.Bytes()
	copy(pubkey[byteLen-len(xBytes):], xBytes)
	yBytes := y.Bytes()
	copy(pubkey[2*byteLen-len(yBytes):], yBytes)

	return
}

func (s ECP) MakeSecret(privkey, pubkey []byte) ([]byte, error) {
	// TODO: check private key

	byteLen := (s.Params().BitSize + 7) >> 3
	if len(pubkey) != 2*byteLen {
		return nil, errors.New("invalid pubkey len")
	}
	p := s.Params().P
	x := new(big.Int).SetBytes(pubkey[:byteLen])
	y := new(big.Int).SetBytes(pubkey[byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, errors.New("invalid pubkey value")
	}
	if !s.IsOnCurve(x, y) {
		return nil, errors.New("pubkey not on the curve")
	}

	xS, _ := s.ScalarMult(x, y, privkey)
	return xS.Bytes(), nil
}
