package dh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECP(t *testing.T) {
	for _, imp := range []DH{
		ECP224,
		ECP256,
		ECP384,
		ECP521,
	} {
		//t.Logf("testing %s", imp)
		sk1, pk1, err := imp.Generate()
		require.NoError(t, err)
		sk2, pk2, err := imp.Generate()
		require.NoError(t, err)

		sec1, err := imp.MakeSecret(sk1, pk2)
		require.NoError(t, err)

		sec2, err := imp.MakeSecret(sk2, pk1)
		require.NoError(t, err)

		require.Equal(t, sec1, sec2)
	}
}
