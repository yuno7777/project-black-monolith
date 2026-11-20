# Black Monolith product roadmap

Start with platform and security teams that operate internal engineering agents.
The developer installs the gateway and tests tool policies in their normal
workflow. The operator decides which tools and actions are allowed and reviews
the resulting audit trail. Use a GitHub issue triage agent as the first pilot.

| Milestone | Work | Exit criteria |
| --- | --- | --- |
| 1. Developer onboarding | Unify local setup, health diagnostics, and agent launch. Document the Claude Code path and the offline gateway demo. Extend the existing portable bundles with signed release provenance and publish pinned container images. | From a clean machine, a developer can diagnose missing dependencies, connect an agent, and see an attributed session event. Measure time to first event against a 10-minute target. |
| 2. Customer-hosted pilot foundations | Bind agent-facing requests to authenticated workload identity and enforce tenant, agent, and session scope. Add scoped credential rotation, deployment manifests, and backup, restore, and rollback procedures. Define outage behavior for reads, writes, telemetry, and revocation. | Verify cross-tenant isolation, credential rotation, revocation propagation, and database restore before accepting shared deployments. |
| 3. GitHub issue triage pilot | Let an agent read issues and draft labels or replies. Require explicit approval for publishing replies or changing labels. Add a versioned policy, an approved tool inventory, and a GitHub PR check for tool schema changes. Record the reviewer, policy version, and action result in the existing audit trail. | In a test repository, a reviewer can approve a proposed change, see the exact action that ran, and revoke the session. Denied, expired, or already-consumed approvals cannot authorize writes. |
| 4. Team operations | Add agent owners, coverage and overdue-review views, Jira incident handoff, retention controls, and redacted evidence exports. Add monitor-to-enforce rollout by agent. | Operators can find uncovered agents, route an incident to its owner, and export a reviewable record. |
| 5. Workload expansion | Pilot redaction with a support copilot. Add source provenance and access-aware retrieval for knowledge assistants. Prioritize additional model providers, framework adapters, and shared VectorAnchor state based on pilot demand. | A second workload uses the same identity, policy, and investigation workflow, with measured latency and false blocks. |

## First implementation slice

Add `monolith init`, `monolith doctor`, and `monolith wrap`. Reuse the existing
credential generator and gateway launcher. `init` preserves an existing `.env`.
`doctor` checks the three service endpoints, the local MCP-Shield binary, and
the launcher’s module-token configuration. Remove the setup instruction that
asks an agent to report the operator token. Cover the CLI in the existing local
tooling CI suite.

## Pilot measurement and packaging

- Keep the local gateway, policy tooling, and demo available as open source.
- Test a paid, customer-hosted pilot for one team and one production workflow.
  Price the initial offer by protected production agent and include deployment support.
- Record time to first protected call, agent coverage, false blocks on normal
  traffic, approval turnaround, and p95 gateway latency. Use the repository’s
  synthetic benchmarks as regression checks and report pilot measurements separately.
