// Command trustbase-bundle converts a genesis trust base published as JSON (the unicity-ids bft-trustbase.<network>.json form, record version 1) into the
// version-2 genesis entry and the one-entry release bundle (tag 39015) that clients load, and prints their identities.
//
//	trustbase-bundle -in bft-trustbase.mainnet.json -out-dir out -name mainnet
//
// writes out/mainnet.bundle.cbor (the file to ship), out/mainnet.bundle.cbor.hex, out/mainnet.genesis.cbor (the bare tag-39000 entry) and out/mainnet.entryid
// (the genesis EntryID, hex: the pin clients compare). The V1 file's own signatures are not carried over: a V2 genesis has none and is authenticated by the
// pin. Only a genesis is converted: epoch 1, no state or change hash, no predecessor.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/unicitynetwork/bft-go-base/types"
)

// BundleTag is the tag of the GetTrustBase response, which is also the release bundle (provisional until registered in unicity-ids).
const BundleTag = 39015

type v1Node struct {
	NodeID string `json:"nodeId"`
	SigKey string `json:"sigKey"`
	Stake  uint64 `json:"stake"`
}

type v1File struct {
	Version           uint64            `json:"version"`
	NetworkID         uint64            `json:"networkId"`
	Epoch             uint64            `json:"epoch"`
	EpochStartRound   uint64            `json:"epochStartRound"`
	RootNodes         []v1Node          `json:"rootNodes"`
	QuorumThreshold   uint64            `json:"quorumThreshold"`
	StateHash         string            `json:"stateHash"`
	ChangeRecordHash  string            `json:"changeRecordHash"`
	PreviousEntryHash string            `json:"previousEntryHash"`
	Signatures        map[string]string `json:"signatures"`
}

// Result is the converted genesis.
type Result struct {
	Entry   []byte // tagged V2 genesis entry
	Bundle  []byte // one-entry release bundle
	EntryID [types.TrustBaseV2IDLen]byte
	Network types.NetworkID
}

func unhex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// Convert turns the JSON of a version-1 genesis trust base into the V2 genesis entry and its one-entry bundle.
func Convert(in []byte) (*Result, error) {
	var f v1File
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("trust base JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trust base JSON: trailing data")
	}
	switch {
	case f.Version != 1:
		return nil, fmt.Errorf("version %d: only the version-1 JSON form is converted", f.Version)
	case f.Epoch != 1:
		return nil, fmt.Errorf("epoch %d: only a genesis (epoch 1) is converted", f.Epoch)
	case f.StateHash != "" || f.ChangeRecordHash != "" || f.PreviousEntryHash != "":
		return nil, fmt.Errorf("a genesis has no state, change or previous hash")
	case f.NetworkID == 0 || f.NetworkID > 0xffff:
		return nil, fmt.Errorf("network id %d out of range", f.NetworkID)
	}
	nodes := make([]*types.NodeInfo, 0, len(f.RootNodes))
	for _, n := range f.RootNodes {
		key, err := unhex(n.SigKey)
		if err != nil {
			return nil, fmt.Errorf("node %q: sigKey: %w", n.NodeID, err)
		}
		nodes = append(nodes, &types.NodeInfo{NodeID: n.NodeID, SigKey: key, Stake: n.Stake})
	}
	// V2 members are sorted by raw node-id bytes; the V1 file's order is not a rule
	slices.SortFunc(nodes, func(a, b *types.NodeInfo) int { return strings.Compare(a.NodeID, b.NodeID) })
	e := types.NewRootTrustBaseV2()
	e.NetworkID = types.NetworkID(f.NetworkID)
	e.Epoch = f.Epoch
	e.EpochStart = f.EpochStartRound
	e.RootNodes = nodes
	e.QuorumThreshold = f.QuorumThreshold
	e.PreviousEntryID = make([]byte, types.TrustBaseV2IDLen)
	if err := e.VerifyGenesis(); err != nil {
		return nil, err // includes: the threshold is not floor(2W/3)+1
	}
	entry, err := e.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	if _, err := types.DecodeRootTrustBaseV2(entry); err != nil {
		return nil, fmt.Errorf("the strict decoder refuses what was encoded: %w", err)
	}
	id, err := e.EntryID()
	if err != nil {
		return nil, err
	}
	bundle, err := encodeBundle(e, entry, id[:])
	if err != nil {
		return nil, err
	}
	return &Result{Entry: entry, Bundle: bundle, EntryID: id, Network: e.NetworkID}, nil
}

// encodeBundle writes the GetTrustBase response layout with status OK:
// [version=1, network, status=0, fromEpoch, effectiveEnd, endEntryID, [entry], null] (bft-core gettrustbase.EncodeBundle).
func encodeBundle(e *types.RootTrustBaseV2, entry, id []byte) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	content, err := enc.Marshal([]any{uint64(1), uint64(e.NetworkID), uint64(0), e.Epoch, e.Epoch, id, []cbor.RawMessage{entry}, nil})
	if err != nil {
		return nil, err
	}
	return enc.Marshal(cbor.RawTag{Number: BundleTag, Content: content})
}

func main() {
	in := flag.String("in", "", "version-1 genesis JSON (unicity-ids bft-trustbase.<network>.json)")
	outDir := flag.String("out-dir", ".", "output directory")
	name := flag.String("name", "", "output file stem, e.g. mainnet")
	flag.Parse()
	if *in == "" || *name == "" {
		flag.Usage()
		os.Exit(2)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r, err := Convert(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *in, err)
		os.Exit(1)
	}
	id := hex.EncodeToString(r.EntryID[:])
	files := map[string][]byte{
		*name + ".bundle.cbor":     r.Bundle,
		*name + ".bundle.cbor.hex": []byte(hex.EncodeToString(r.Bundle) + "\n"),
		*name + ".genesis.cbor":    r.Entry,
		*name + ".entryid":         []byte(id + "\n"),
	}
	for fn, b := range files {
		if err := os.WriteFile(filepath.Join(*outDir, fn), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s: network %d, genesis entryId %s, entry %d bytes, bundle %d bytes\n", *name, r.Network, id, len(r.Entry), len(r.Bundle))
}
