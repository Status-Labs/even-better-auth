# Security policy

even better auth is pre-1.0 and has not had an independent security review. Don't rely on it
in production yet.

## Reporting a vulnerability

Please report vulnerabilities privately, not in public issues or pull requests.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository
and choose "Report a vulnerability".

Please include the affected version or commit, a description of the issue, and steps or a
proof of concept to reproduce it. You can expect an acknowledgement within a few days. Once a
fix is released, the advisory will be published with credit to you unless you prefer
otherwise.

## Scope

Issues in this Rust port are in scope. If the issue also affects the TypeScript
[better-auth](https://github.com/better-auth/better-auth) (the same flaw in shared protocol
logic, for example), please report it to that project as well, following its security policy.

## Supported versions

Only the latest commit on `main` (and, once published, the latest release) receives fixes.
