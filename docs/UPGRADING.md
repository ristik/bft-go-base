# Upgrade / rollout

## Stop-all upgrade required

The strict `VerifyHash` / `VerifyBytes` rule in `crypto` (exactly 65 bytes, `1 <= r,s < n`, low-S, recovery id
`v` in 0..3, recovered key equal to the trusted key) changes which seals and quorum certificates (QCs) reach quorum.

`VerifyQuorumSignatures` adds up the stake of every signature that passes `VerifyBytes`. A signature that an old node
accepts and a new node rejects changes the count. One faulty root validator, or any peer relaying a vote or a seal,
can therefore make old and new nodes disagree on whether the same seal or QC has quorum. That stalls rounds for as long
as the versions are mixed.

Example: 4 root nodes (quorum threshold 3), a seal signed by exactly 3 of them, then one of the signatures is changed.

| change to one signature        | old rule (before strict `VerifyHash`) | new rule (strict `VerifyHash`)                                |
|--------------------------------|---------------------------------------|---------------------------------------------------------------|
| `v ^= 2` (other recovery branch) | `seal.Verify(tb)` returns nil         | `quorum not reached, signed_votes=2 quorum_threshold=3`       |
| `v = 27`                       | nil                                   | quorum not reached                                            |
| truncated to 64 bytes          | nil                                   | quorum not reached                                            |

QCs in bft-core use the same `VerifyQuorumSignatures`, so they are affected in the same way.

**Supported rollout: stop-all.** All root validators, all shard validators and all aggregators must be stopped and
upgraded together, then restarted on the new version. A rolling upgrade and activation of the strict rule at an epoch
boundary ("per-epoch activation") are **not supported**: there is no version negotiation and no activation switch in
the library, so a mixed-version network can disagree on the same seal or QC.

The same assumption covers the other consensus-relevant fixes in the same release (stricter `ShardingScheme.IsValid`,
which now rejects incomplete schemes). Nodes on different versions can disagree on those too.

## Honest signers are unaffected

Every signing path in bft-core (votes, proposals, timeouts, certification requests) and in aggregator-go uses the
in-memory signer, which produces 65-byte, low-S signatures with `v` in {0,1}. These pass both the old and the new rule,
so no signer needs to change its keys or its signing code, and an honest network does not change its behaviour
after the upgrade.

## Merge and release order

bft-go-base → bft-core → aggregator-go. Each downstream module takes the new bft-go-base version first; the stop-all
upgrade then deploys the three together.
