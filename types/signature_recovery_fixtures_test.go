package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// Shared signature-recovery regression fixtures (O3): the canonical rule is a 65-byte r||s||v signature, low-S,
// v in 0..3, and the key recovered with v must equal the trusted key. The JSON is meant to be consumed by the
// Rust and JS verifiers as well. Regenerate with: go test ./types -run TestSignatureRecoveryFixtures -update-sigfixtures

var updateSigFixtures = flag.Bool("update-sigfixtures", false, "rewrite testdata/signature-recovery/v1/vectors.json")

const sigFixturePath = "../testdata/signature-recovery/v1/vectors.json"

var secpN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

type sigVector struct {
	Name   string `json:"name"`
	Sig    string `json:"signature"`
	Accept bool   `json:"accept"`
	Note   string `json:"note,omitempty"`
}

type primitiveFixture struct {
	PublicKey string      `json:"publicKeyCompressed"`
	Hash      string      `json:"messageHashSha256"`
	Message   string      `json:"messageUtf8"`
	Vectors   []sigVector `json:"vectors"`
}

type sealCase struct {
	Name   string `json:"name"`
	Seal   string `json:"sealCbor"`
	Accept bool   `json:"accept"`
	Note   string `json:"note,omitempty"`
}

type sealFixture struct {
	Description string     `json:"description"`
	NetworkID   uint16     `json:"networkId"`
	Epoch       uint64     `json:"epoch"`
	Quorum      uint64     `json:"quorumThreshold"`
	Nodes       []nodeFx   `json:"nodes"`
	TrustBase   string     `json:"trustBaseCbor"`
	Cases       []sealCase `json:"cases"`
}

type nodeFx struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKeyCompressed"`
	Stake     uint64 `json:"stake"`
}

type sigFixtureFile struct {
	Spec      []string         `json:"spec"`
	Primitive primitiveFixture `json:"primitive"`
	Seal      sealFixture      `json:"seal"`
}

func fixedSigner(t *testing.T, n int) abcrypto.Signer {
	sk := sha256.Sum256([]byte("unicity-o3-fixture-key-" + strconv.Itoa(n))) // public deterministic test keys
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(sk[:])
	require.NoError(t, err)
	return s
}

func withV(sig []byte, v byte) []byte { c := bytes.Clone(sig); c[64] = v; return c }

// highS returns the same (r, n-s) with the flipped parity: a mathematically valid but non-canonical signature.
func highS(sig []byte) []byte {
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(secpN, s)
	c := bytes.Clone(sig)
	copy(c[32:64], make([]byte, 32))
	s.FillBytes(c[32:64])
	c[64] ^= 1
	return c
}

func buildSigFixtures(t *testing.T) sigFixtureFile {
	signer := fixedSigner(t, 0)
	ver, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := ver.MarshalPublicKey()
	require.NoError(t, err)
	msg := []byte("unicity o3 recovery fixture")
	h := sha256.Sum256(msg)
	sig, err := signer.SignBytes(msg)
	require.NoError(t, err)
	require.Len(t, sig, 65)
	require.LessOrEqual(t, sig[64], byte(1))

	vec := func(name string, s []byte, note string) sigVector {
		accept := ver.VerifyHash(s, h[:]) == nil
		return sigVector{Name: name, Sig: hex.EncodeToString(s), Accept: accept, Note: note}
	}
	zero := make([]byte, 32)
	var vs []sigVector
	vs = append(vs, vec("valid", sig, "r||s||v as produced by the signer"))
	for _, v := range []byte{0, 1, 2, 3, 4, 27, 28, 31, 255} {
		if v == sig[64] {
			continue
		}
		vs = append(vs, vec("recovery-id-"+strconv.Itoa(int(v)), withV(sig, v), "same r,s; only v changed"))
	}
	vs = append(vs, vec("recovery-id-xor-1", withV(sig, sig[64]^1), "stays in range but recovers another key"))
	vs = append(vs, vec("high-s-flipped-parity", highS(sig), "(r, n-s, v^1): valid ECDSA, non-canonical"))
	vs = append(vs, vec("high-s-same-v", withV(highS(sig), sig[64]), ""))
	vs = append(vs, vec("compact-64", sig[:64], "no recovery id: not a canonical seal signature"))
	vs = append(vs, vec("truncated-63", sig[:63], ""))
	vs = append(vs, vec("extended-66", append(bytes.Clone(sig), 0), ""))
	vs = append(vs, vec("empty", []byte{}, ""))
	r0 := bytes.Clone(sig)
	copy(r0[:32], zero)
	vs = append(vs, vec("r-zero", r0, ""))
	s0 := bytes.Clone(sig)
	copy(s0[32:64], zero)
	vs = append(vs, vec("s-zero", s0, ""))
	sn := bytes.Clone(sig)
	secpN.FillBytes(sn[32:64])
	vs = append(vs, vec("s-equals-n", sn, ""))
	rn := bytes.Clone(sig)
	secpN.FillBytes(rn[:32])
	vs = append(vs, vec("r-equals-n", rn, ""))
	for _, v := range vs {
		if v.Name == "valid" {
			require.True(t, v.Accept)
		} else if v.Accept {
			t.Fatalf("vector %s unexpectedly accepted", v.Name)
		}
	}

	// seal level: 4 admitted nodes, quorum 3
	var nodes []*NodeInfo
	var fxNodes []nodeFx
	signers := map[string]abcrypto.Signer{}
	for i := 1; i <= 4; i++ {
		id := "node" + strconv.Itoa(i)
		s := fixedSigner(t, i)
		v, err := s.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &NodeInfo{NodeID: id, SigKey: pk, Stake: 1})
		fxNodes = append(fxNodes, nodeFx{ID: id, PublicKey: hex.EncodeToString(pk), Stake: 1})
		signers[id] = s
	}
	tb, err := NewTrustBase(NetworkLocal, nodes, WithEpoch(1))
	require.NoError(t, err)
	tbBytes, err := tb.MarshalCBOR()
	require.NoError(t, err)
	seal := func(mutate func(m SignatureMap)) *UnicitySeal {
		sl := &UnicitySeal{Version: 1, NetworkID: NetworkLocal, RootChainRoundNumber: 7, Epoch: 1, Timestamp: GenesisTime + 1,
			PreviousHash: bytes.Repeat([]byte{1}, 32), Hash: bytes.Repeat([]byte{2}, 32)}
		for id, s := range signers {
			require.NoError(t, sl.Sign(id, s))
		}
		if mutate != nil {
			mutate(sl.Signatures)
		}
		return sl
	}
	flip := func(id string) func(SignatureMap) {
		return func(m SignatureMap) { m[id] = withV(m[id], m[id][64]^1) }
	}
	var cases []sealCase
	add := func(name, note string, sl *UnicitySeal) {
		b, err := sl.MarshalCBOR()
		require.NoError(t, err)
		cases = append(cases, sealCase{Name: name, Seal: hex.EncodeToString(b), Accept: sl.Verify(tb) == nil, Note: note})
	}
	add("valid-all-four", "", seal(nil))
	add("one-v-flipped-quorum-still-met", "bad recovery id contributes zero votes; surplus invalid signature tolerated", seal(flip("node1")))
	add("two-v-flipped-quorum-lost", "only 2 valid votes of 3 needed", seal(func(m SignatureMap) { flip("node1")(m); flip("node2")(m) }))
	add("one-signature-dropped-quorum-met", "", seal(func(m SignatureMap) { delete(m, "node4") }))
	add("one-dropped-one-v-flipped-quorum-lost", "", seal(func(m SignatureMap) { delete(m, "node4"); flip("node1")(m) }))
	add("one-v-out-of-range-quorum-met", "v=4 is rejected, three valid signatures remain", seal(func(m SignatureMap) { m["node1"] = withV(m["node1"], 4) }))
	add("two-high-s-quorum-lost", "", seal(func(m SignatureMap) { m["node1"] = highS(m["node1"]); m["node2"] = highS(m["node2"]) }))
	add("surplus-compact-quorum-met", "a surplus 64-byte compact entry contributes zero votes next to a met quorum", seal(func(m SignatureMap) { m["node4"] = m["node4"][:64] }))
	add("two-compact-quorum-lost", "", seal(func(m SignatureMap) { m["node1"] = m["node1"][:64]; m["node2"] = m["node2"][:64] }))
	add("copied-signature-under-other-id-quorum-lost", "node2/node3 carry node1's signature", seal(func(m SignatureMap) { m["node2"] = m["node1"]; m["node3"] = m["node1"] }))
	for _, c := range cases {
		switch c.Name {
		case "valid-all-four", "one-v-flipped-quorum-still-met", "one-signature-dropped-quorum-met", "one-v-out-of-range-quorum-met", "surplus-compact-quorum-met":
			require.True(t, c.Accept, c.Name)
		default:
			require.False(t, c.Accept, c.Name)
		}
	}

	return sigFixtureFile{
		Spec: []string{
			"Each signature counted toward a unicity seal quorum is exactly 65 bytes r[32]||s[32]||v[1] over SHA-256 of the seal's signature-free CBOR.",
			"1 <= r,s < n; low-S (s <= n/2); v in 0..3 (no 27/28, no EIP-155).",
			"The public key recovered from (hash, r, s, v) must equal the trusted key of the claimed node ID; a range check on v is not enough.",
			"A signature that does not conform contributes zero votes. The seal is accepted iff the stake of conforming signatures from distinct admitted node IDs reaches the quorum threshold.",
			"64-byte compact r||s signatures are not canonical seal signatures.",
		},
		Primitive: primitiveFixture{PublicKey: hex.EncodeToString(pub), Hash: hex.EncodeToString(h[:]), Message: string(msg), Vectors: vs},
		Seal: sealFixture{Description: "4 nodes, stake 1 each, quorum 3, network local, epoch 1", NetworkID: uint16(NetworkLocal), Epoch: 1,
			Quorum: tb.QuorumThreshold, Nodes: fxNodes, TrustBase: hex.EncodeToString(tbBytes), Cases: cases},
	}
}

func TestSignatureRecoveryFixtures(t *testing.T) {
	got, err := json.MarshalIndent(buildSigFixtures(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *updateSigFixtures {
		require.NoError(t, os.MkdirAll(filepath.Dir(sigFixturePath), 0o755))
		require.NoError(t, os.WriteFile(sigFixturePath, got, 0o644))
	}
	want, err := os.ReadFile(sigFixturePath)
	require.NoError(t, err, "regenerate with -update-sigfixtures")
	require.Equal(t, string(want), string(got), "fixtures are stale; regenerate with -update-sigfixtures")
}

// The committed JSON (what Rust/JS consume) is replayed against the Go verifiers.
func TestSignatureRecoveryFixturesReplay(t *testing.T) {
	raw, err := os.ReadFile(sigFixturePath)
	require.NoError(t, err)
	var f sigFixtureFile
	require.NoError(t, json.Unmarshal(raw, &f))

	pub, _ := hex.DecodeString(f.Primitive.PublicKey)
	hash, _ := hex.DecodeString(f.Primitive.Hash)
	ver, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	for _, v := range f.Primitive.Vectors {
		sig, _ := hex.DecodeString(v.Sig)
		require.Equal(t, v.Accept, ver.VerifyHash(sig, hash) == nil, v.Name)
		require.Equal(t, v.Accept, ver.VerifyBytes(sig, []byte(f.Primitive.Message)) == nil, v.Name)
	}
	// the compact primitive is a separate contract
	valid, _ := hex.DecodeString(f.Primitive.Vectors[0].Sig)
	require.NoError(t, ver.(abcrypto.CompactVerifier).VerifyCompactHash(valid[:64], hash))
	require.Error(t, ver.(abcrypto.CompactVerifier).VerifyCompactHash(valid, hash))

	tbRaw, _ := hex.DecodeString(f.Seal.TrustBase)
	tb := NewRootTrustBaseV1()
	require.NoError(t, Cbor.Unmarshal(tbRaw, tb))
	for _, c := range f.Seal.Cases {
		raw, _ := hex.DecodeString(c.Seal)
		var s UnicitySeal
		require.NoError(t, Cbor.Unmarshal(raw, &s), c.Name)
		require.Equal(t, c.Accept, s.Verify(tb) == nil, c.Name)
		require.Equal(t, c.Accept, TrustBaseSealVerifier(tb).VerifySeal(&s) == nil, c.Name)
	}
}
