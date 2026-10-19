package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// The frozen B1 profile verifies its compact (64-byte) witnesses through this explicit entry point from outside the package, so it has to stay exported
// and reachable from the verifier returned by NewVerifierSecp256k1, while Verifier.VerifyBytes is the strict 65-byte rule.
func TestCompactVerifierIsExportedForExternalConsumers(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)

	data := []byte("b1 compact witness")
	sig, err := signer.SignBytes(data)
	require.NoError(t, err)
	require.Len(t, sig, 65)

	compact, ok := verifier.(abcrypto.CompactVerifier)
	require.True(t, ok, "the secp256k1 verifier implements abcrypto.CompactVerifier")
	require.NoError(t, compact.VerifyCompactBytes(sig[:64], data), "the 64-byte form verifies on the explicit compact path")
	require.Error(t, compact.VerifyCompactBytes(sig[:64], []byte("other")))
	require.Error(t, verifier.VerifyBytes(sig[:64], data), "VerifyBytes is the strict 65-byte rule")
	require.NoError(t, verifier.VerifyBytes(sig, data))
}
