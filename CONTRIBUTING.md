# Contributing

Thank you for the interest. Sekisho is **not accepting pull requests at this
time** — the author is still solidifying the early architecture as a single
maintainer.

## Issues are welcome

Bug reports, operational pain points, and design questions are very welcome
on GitHub:

<https://github.com/naoto256/sekisho/issues>

For bug reports, please include:

- Sekisho version (note: `--version` is not yet wired up; use `show version`
  inside `sekisho-cli`, or grep the daemon startup log)
- Reproduction steps (split configure-time vs. runtime if applicable)
- Expected vs. actual behavior
- Relevant logs (`journalctl -u sekishod`, plus any audit events)

## Why PRs are paused

- The architecture is still evolving ahead of 1.0, including the boundaries
  around encryption, HA, and federated authentication.
- Code review capacity for parallel contributors is not there yet
- This phase needs the freedom to land compatibility-breaking refactors
  without coordinating with external work

PRs may reopen later once the public surface stabilizes, but there is no
fixed timeline for that today.

## Contact

- General questions and bug reports: GitHub issues
- Security vulnerabilities: see [`SECURITY.md`](SECURITY.md) (GHSA private)

## License of future contributions

When contributions reopen, they will be accepted under the project's dual
MIT / Apache-2.0 license. No CLA is planned.
