# Pull Request

## Description
<!-- What does this change and why? -->

## Related issue
<!-- e.g. Closes #12 -->

## Testing done
<!-- How did you verify this? Check all that apply and add details. -->
- [ ] `cargo test` (mcp-shield)
- [ ] `python -m pytest tests/` (vector-anchor / trace-audit)
- [ ] `npm run build` (dashboard)
- [ ] Ran the relevant `fixtures/run_demo.sh` / `run_full_demo.sh`
- [ ] Other (describe):

## Checklist
- [ ] No secrets, API keys, or hardcoded local paths added
- [ ] Preserved the shared event shape (`timestamp_ms`, `module`, `event_type`, `severity`, `details`)
- [ ] Updated the relevant README(s) if behavior changed
