# policies/network

Network policy:

- **Phase 1:** Tailscale ACLs — only Warpgate's port is reachable from the
  agent; direct `sshd` is technically blocked (SR1, threat T5)
- **Phase 3:** default-deny egress for the agent user

See [docs/threat-model.md](../../docs/threat-model.md) (T3, T4, T5).
