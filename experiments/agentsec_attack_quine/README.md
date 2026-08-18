# Replay-gated attack quine laboratory

This is an **experimental search harness**, not the current Kaggle submission.
The submission control remains `submissions/agentsec-v58-public-recovery/`, whose
attack bytes match public notebooks reported at 89.145 and 89.280.

The laboratory implements the useful part of a quine without source rewriting:
its strategy is data, it can serialize that strategy, mutate it, test the
mutations against the live competition environment, and export only candidates
that pass repeated fresh replays.  The immutable public strategy is always kept
in the population as a control.

This follows the part of STAC that transfers to this competition:

1. generate small prompt/tool-chain variants;
2. execute them in the environment;
3. require the scored predicate to survive fresh replay;
4. rank by replay-stable score per second;
5. export ordinary static `AttackCandidate` objects.

It deliberately does **not** use an LLM to rewrite Python. Symbolic mutations are
cheap, deterministic, auditable, and leave most of the run budget for validating
candidates. The search never displaces the control merely because a mutation
looked good once.

Run its tests with:

```powershell
python -m pytest experiments/agentsec_attack_quine/test_attack_quine.py -q
```

Do not promote this laboratory to a Kaggle submission unless it beats the public
control under identical replay checks and a held-out seed/model condition.

