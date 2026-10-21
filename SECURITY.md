# Security policy

## Scope of this project

SecurityAI generates exploit payloads and **tests them against targets**. The scope gate
(`exploitgym/scope.yaml`, lab mode by default) is a safety feature, not a suggestion: it
refuses anything that is not loopback, a private range or an explicitly allowed domain.

If you find a way to make the framework test a host outside the configured scope — a
redirect, a DNS-rebinding trick, an SSRF in the recon crawler, a proxy bypass — that is a
security bug in this repository and we want to hear about it.

## Reporting

Open a [private security advisory](https://docs.github.com/code-security/security-advisories)
on this repository, or email the maintainer if advisories are unavailable. Please do not
open a public issue for anything that could be used against a live system.

Include: what you did, what you expected, what happened, and the smallest configuration that
reproduces it. A failing test is the ideal report.

## Not in scope

- Payloads that fail to fire. Precision and recall of the models is research, not a
  vulnerability — open an issue instead.
- Anything requiring a model that is not distributed here.
- Reports about third-party targets. If you use this against a system you do not own, that is
  outside this project's scope and outside its licence's intent.
