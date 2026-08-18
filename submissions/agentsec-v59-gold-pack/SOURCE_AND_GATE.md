# AgentSec v59 gold pack

Pushed and submitted 2026-08-15.

- Kernel: https://www.kaggle.com/code/issacizrealdavis/agentsec-v59-gold-pack (version 1)
- Competition ref: `55520031` — `SubmissionStatus.PENDING` at 2026-08-15 04:30:53 UTC
- Message: `v59 gold-pack: public 89 parent, generate wall 0.98, hops=1 fill, replay pack 0.998`

## Why this version can score better than the first 0.998 draft

Raising `REPLAY_SAFE_FRAC` on **both** clocks was wrong. `wall_deadline` is
generate time. Hosted **generation timeout is still fatal**. 0.998 * 9000s = 8982s
plus a 75-146s warm-up leaves ~18s of cushion. That is how a "gold pack" blanks.

This packet:

- keeps **generate** at the public parent wall `GENERATE_SAFE_FRAC = 0.98`
- packs **replay** only, `REPLAY_SAFE_FRAC = 0.998`
- probes at `PROBE_HOPS = 1` (same fire, cheaper fill; 12/12 in the hops-1 note)
- charges replay at `REPLAY_COST_COEF = 1.75` so hops-1 elapsed is not treated as hops-8

Local clock test (budget 400s, hop1=5s, hop8=9s): v59 must return **more**
candidates than the public 0.98/hops=8 parent and stay inside `0.98 * budget`.

Board arithmetic is unchanged: gold 90.900 needs ~1010 fires; public 89.280 is 992.
This is still a prediction on the real grader. The **sure** beat of our 85.500 is
the untouched v58 parent. v59 is the gold attempt that no longer lengthens generate.

## Integrity

Expected SHA-256 for `attack.py` is `073937856CC325E657F9B43877296A53EBEDABF297073757F95E80C288BA7431`.

```powershell
python submissions/build_v59_gold_pack.py
python -m pytest submissions/agentsec-v59-gold-pack/test_public_recovery.py -q
python -m aicomp_sdk.cli.main validate redteam submissions/agentsec-v59-gold-pack/attack.py
```
