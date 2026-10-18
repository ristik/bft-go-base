package types

import (
	"crypto"
	"testing"
)

// FuzzUnicityCertificateVerify decodes arbitrary bytes as a UnicityCertificate and runs the verification path on
// whatever decodes. Nothing a peer can put on the wire may panic: a decode error, a verification error or (for the
// valid seed) success are the only outcomes.
//
// Bounded run (iteration count, not wall-clock):
//
//	go test ./types -run '^$' -fuzz FuzzUnicityCertificateVerify -fuzztime 2000000x
func FuzzUnicityCertificateVerify(f *testing.F) {
	fix := newUCFix(f)
	add := func(uc *UnicityCertificate) {
		if b, err := uc.MarshalCBOR(); err == nil {
			f.Add(b)
		}
	}
	add(fix.uc)
	// nulls where the decoder produces nil pointers or empty collections
	withSteps := func(steps []*PathItem) {
		uc := *fix.uc
		utc := *fix.uc.UnicityTreeCertificate
		utc.HashSteps = steps
		uc.UnicityTreeCertificate = &utc
		add(&uc)
	}
	withSteps([]*PathItem{nil})
	withSteps(append(append([]*PathItem(nil), fix.uc.UnicityTreeCertificate.HashSteps...), nil))
	withSteps(nil)
	for _, mut := range []func(*UnicityCertificate){
		func(uc *UnicityCertificate) { uc.InputRecord = nil },
		func(uc *UnicityCertificate) { uc.UnicitySeal = nil },
		func(uc *UnicityCertificate) { uc.UnicityTreeCertificate = nil },
		func(uc *UnicityCertificate) { uc.ShardTreeCertificate.SiblingHashes = nil },
		func(uc *UnicityCertificate) { uc.ShardTreeCertificate.SiblingHashes = [][]byte{nil, nil} },
		func(uc *UnicityCertificate) { uc.ShardTreeCertificate.Shard = ShardID{} },
		func(uc *UnicityCertificate) { uc.UnicitySeal.Signatures = SignatureMap{"x": nil} },
		func(uc *UnicityCertificate) { uc.UnicitySeal.Signatures = nil },
	} {
		uc := *fix.uc
		seal := *fix.uc.UnicitySeal
		uc.UnicitySeal = &seal
		mut(&uc)
		add(&uc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var uc UnicityCertificate
		if err := uc.UnmarshalCBOR(data); err != nil {
			return
		}
		// the verification entry point, with the expectations of the fixture and with other ones
		_ = uc.Verify(fix.tb, crypto.SHA256, fix.partition, fix.shard, fix.conf)
		_ = uc.Verify(fix.tb, crypto.SHA256, fix.partition, ShardID{}, nil)
		_ = uc.IsValid(fix.partition, fix.shard, fix.conf)
		// the parts callers use without IsValid
		if uc.UnicityTreeCertificate != nil {
			_, _ = uc.UnicityTreeCertificate.EvalAuthPath(fix.uc.TRHash, crypto.SHA256)
		}
		if uc.InputRecord != nil {
			_, _ = uc.ShardTreeCertificate.ComputeCertificateHash(uc.InputRecord, uc.TRHash, uc.ShardConfHash, crypto.SHA256)
		}
		_ = uc.UnicitySeal.Verify(fix.tb)
		_, _ = uc.Hash(crypto.SHA256)
	})
}
