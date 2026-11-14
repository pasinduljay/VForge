# Runner & Scanner Execution Plane (Planned Phases 4–8, 15)

- `agent/` — Dedicated Linux VM mTLS runner agent (Phase 4)
- `executor/` — Hardened ephemeral container executor (Phase 4)
- `network-policy/` — Scope-aware egress gateway (Phase 4)
- `images/` — Pinned scanner Dockerfiles (Phase 5+: OpenGrep, Gitleaks, Syft, Grype, Checkov, ZAP, Nuclei, Nmap, testssl.sh, Wapiti, SQLMap, Strix)

Not active in Phase 0. No scanner images or Docker socket access exist in the control plane.
