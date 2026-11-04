package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

// The unicity-ids genesis files (github.com/unicitynetwork/unicity-ids, main 44c6214), converted. The entry ids are the values the V2 format examples of the
// proposal carry; the bundles are one-entry GetTrustBase responses.
var cases = []struct{ file, entryID, network string }{
	{"testdata/bft-trustbase.mainnet.json", "0b6f8143e19e2a585be3534e8f1062f36c3b9621e506158f10abfbc9a56f4e4c", "1"},
	{"testdata/bft-trustbase.testnet2.json", "4b49eb2bb0729051b89a48668fd6ef1fda284aad2e10b7d5f23aad4b5faef37f", "4"},
}

func TestConvertTheUnicityIDsGenesisFiles(t *testing.T) {
	for _, c := range cases {
		in, err := os.ReadFile(c.file)
		require.NoError(t, err)
		r, err := Convert(in)
		require.NoError(t, err, c.file)
		require.Equal(t, c.entryID, hex.EncodeToString(r.EntryID[:]), c.file)
		// the bare entry is what the strict decoder accepts, and its identity is the file's SHA-256 (null signatures)
		e, err := types.DecodeRootTrustBaseV2(r.Entry)
		require.NoError(t, err)
		require.NoError(t, e.VerifyGenesis())
		require.Equal(t, 4, len(e.RootNodes))
		// a one-entry bundle: tag 39015 (d99867), the 8-element response, version 1, status OK, from = end = epoch 1, the entry embedded verbatim
		require.True(t, bytes.HasPrefix(r.Bundle, []byte{0xd9, 0x98, 0x67, 0x88, 0x01}), c.file)
		require.True(t, bytes.Contains(r.Bundle, r.Entry), "entry embedded verbatim")
		require.True(t, bytes.HasSuffix(r.Bundle, []byte{0xf6}), "null cursor")
	}
}

func TestConvertRefusesWhatIsNotAGenesis(t *testing.T) {
	good, err := os.ReadFile(cases[0].file)
	require.NoError(t, err)
	edit := func(old, repl string) []byte {
		require.Contains(t, string(good), old)
		return []byte(strings.Replace(string(good), old, repl, 1))
	}
	for name, in := range map[string][]byte{
		"version 2":         edit(`"version": 1`, `"version": 2`),
		"epoch 2":           edit(`"epoch": 1`, `"epoch": 2`),
		"state hash":        edit(`"stateHash": ""`, `"stateHash": "0x11"`),
		"wrong threshold":   edit(`"quorumThreshold": 3`, `"quorumThreshold": 2`),
		"unknown field":     edit(`"epoch": 1`, `"epoch": 1, "extra": 1`),
		"bad key":           edit(`0x03059e30`, `0x03059e31`),
		"trailing data":     append(append([]byte{}, good...), []byte(" {}")...),
		"network zero":      edit(`"networkId": 1`, `"networkId": 0`),
		"not json":          []byte("nope"),
		"duplicate members": edit(`"nodeId": "16Uiu2HAmF9Mq9pH9yUTdao3TpJeFZY9oX9gyMqfxggVA4fNmzmXr"`, `"nodeId": "16Uiu2HAkvk4EpXoyh7SVLTX3TcsZkjbni5jY1sBgJ7qCEWfx1Gma"`),
	} {
		_, err := Convert(in)
		require.Error(t, err, name)
	}
}

func TestMemberOrderInTheFileIsNotARule(t *testing.T) {
	good, err := os.ReadFile(cases[0].file)
	require.NoError(t, err)
	a, err := Convert(good)
	require.NoError(t, err)
	var f map[string]any
	require.NoError(t, json.Unmarshal(good, &f))
	nodes := f["rootNodes"].([]any)
	slices.Reverse(nodes)
	reordered, err := json.Marshal(f)
	require.NoError(t, err)
	b, err := Convert(reordered)
	require.NoError(t, err)
	require.Equal(t, a.Bundle, b.Bundle, "members reversed in the file, same entry")
}
