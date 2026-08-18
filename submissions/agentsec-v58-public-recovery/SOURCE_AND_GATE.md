# AgentSec v58 public recovery

This is a byte-exact recovery candidate built from public Kaggle code. It is staged only;
it has not been pushed, run, or submitted from this directory.

## Why this parent

The same embedded `attack.py` bytes occur in four independently published notebooks:

- `foysalemonshanto/ai-agent-security-v15`
- `dimong4/ai-agent-security`
- `nikitagajbhiye30/ai-security-0011`
- `nctuan/jed-v25`

The Kaggle UI reported `89.280` for `ai-security-0011` and `89.145` for `jed-v25` on
2026-08-14. Our protected champion is `85.500`. The identical v34 champion bytes scored
`84.420` and `85.500`, so their observed rerun spread is `1.080`; the public parent's
reported lift is larger than that spread.

This does **not** claim that v58 will reproduce either score after the evaluator refresh.
Those are public-board observations, not local validation.

## Mechanism kept intact

- One `http.post` per candidate (`BURST_K = 1`, `SLOW_MULTIPOST_N = 1`).
- Live validation-fill retains only candidates that actually fired.
- Eight initial trials classify the target by latency.
- The slow branch uses the published reasoning-channel suffix.
- Replay-safe sizing stays at the published `0.98` fraction.
- No v55-v57 PP/PPP, 18-arm selector, or confused-deputy additions.

## Current-evaluator boundary

The August evaluator update normalizes Gemma tool calls and preserves partial replay
scores after replay timeout. Attack-generation timeout remains fatal. Organizers also
warned that harness-specific behavior may not transfer to final ranking. Therefore this
candidate restores the strongest public parent but does not tune closer to the timeout
wall or add another parser-specific arm.

## Integrity

Expected SHA-256 for `attack.py`:

`614176A339E71B80A71C9CF5035C6BAB486B5C5A82C4F14D9E8A1E1417424F9F`

The test suite verifies that the notebook embeds those exact bytes and that a static
25-candidate run obeys the replay contract.

## Attribution

This code was downloaded from the public Kaggle notebooks above for use in the same
competition. Keep these source references in the solution write-up. The downloaded
Kaggle metadata did not expose a separate source-code license field.

## Gate commands

```powershell
python -m pytest v58_public_recovery/test_public_recovery.py -q
$env:PYTHONIOENCODING='utf-8'
$env:PYTHONUTF8='1'
python -m aicomp_sdk.cli.main validate redteam C:\dev\agentsec\v58_public_recovery\attack.py
```

Do not run `kaggle kernels push` or spend a competition submission until explicitly
authorized.
