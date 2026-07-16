# MCP-Shield — calibration / repeatability results

_Reproduce by running `bash fixtures/run_demo.sh` repeatedly. Detection is
deterministic (HMAC-SHA256 over a canonical schema serialization), so every
trial must produce identical hashes and the same 8/8 assertions._

## Trial table (5 runs of the clean → rug-pull demo)

| Trial | Baseline registered | Schema mismatch | Suspicious desc | Blocked (enforce) | Re-flag (monitor) | Checks | Result |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | Y | Y | Y | Y | Y | 8/8 | PASS |
| 2 | Y | Y | Y | Y | Y | 8/8 | PASS |
| 3 | Y | Y | Y | Y | Y | 8/8 | PASS |
| 4 | Y | Y | Y | Y | Y | 8/8 | PASS |
| 5 | Y | Y | Y | Y | Y | 8/8 | PASS |

## Determinism

- **5 / 5 trials passed all 8 assertions** with no flakiness from timing or ordering.
- Trusted `read_file` schema fingerprint (truncated): `0d1c0b7a4558cb7e`
- Mutated `read_file` schema fingerprint (truncated): `e1b8838a08626ded`
- Identical across all trials — the HMAC fingerprint is a pure function of the schema.
