# Privacy and security

Fleet Audit is a local, read-only inventory tool. Its default output is designed to be suitable for sharing during a technical review, but every user must still inspect a snapshot before publishing it.

## Data included

Version 0.1 snapshots may include:

- operating-system, kernel and architecture details;
- CPU description, logical processor count and total memory;
- block-device names, types and sizes;
- mount points, filesystem types, capacities and utilisation;
- network interface names and operational state;
- listening protocol, port and abstract bind scope;
- installed package names, versions and architectures;
- enabled service names;
- pending-update count and reboot-required state;
- check results and non-sensitive collection diagnostics.

Package, service, interface and mount-point names can still reveal a machine's purpose. Treat snapshots as operational records, even though direct identifiers are excluded.

## Data excluded

The version 0.1 schema has no fields for:

- hostnames or machine IDs;
- usernames or account lists;
- IP or MAC addresses;
- device serial numbers, asset tags or filesystem UUIDs;
- process arguments or environment variables;
- credentials, keys or tokens;
- logs, shell history or arbitrary file contents.

The schema rejects unknown properties. This prevents an accidental extra field such as `hostname` from passing validation unnoticed.

## Collection boundary

Collectors must run without root privileges and must never invoke `sudo`. They may read standard operating-system interfaces and execute fixed, read-only commands. They must not install packages, refresh package indexes, change services, modify configuration or make network requests.

Python creates a temporary collection workspace with owner-only permissions. Collectors may write only to that workspace. The application removes it after success and every handled failure. The published snapshot also uses owner-only permissions.

## Failure semantics

Unavailable or inaccessible data is not evidence that a machine is compliant. Fleet Audit records missing capabilities as `unavailable`, check results as `SKIP` or `ERROR`, and the overall collection as `partial` where appropriate. Validation and comparison preserve these states.

## Safe demonstrations

Committed fixtures are synthetic. Do not build examples from Microsoft, Google, Astreya, client or personal machines. Live testing must use a disposable environment with no employer or personal data.
