# Reproducible submission packets

This directory holds locally gated competition candidates. A packet is not evidence that
it has been pushed to Kaggle or submitted for scoring; each packet records that state in
its own receipt.

## AI Agent Security

- [`agentsec-v58-public-recovery/`](agentsec-v58-public-recovery/) restores the exact
  single-post, replay-safe public parent reported at 89.145 and 89.280. It deliberately
  drops the locally attractive v55-v57 additions that scored below the protected 85.500
  champion. See its `SOURCE_AND_GATE.md` for attribution, evaluator boundaries, hashes,
  and exact verification commands.
- [`agentsec-v59-gold-pack/`](agentsec-v59-gold-pack/) is the public parent with
  generate pinned at `0.98` (fatal if breached), replay packed to `0.998`, and
  `PROBE_HOPS=1` so the extra fires are collected inside that generate wall.
  Clock test requires more candidates than hops=8 / 0.98. Not pushed.
