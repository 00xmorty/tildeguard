# v0.1.0

Initial read-only POSIX PATH explainer for literal leading tildes, empty entries and relative directories.

- Value-free text and schema-versioned JSON reports with 1-based entry numbers.
- Optional --check exit codes distinguish review findings from absent PATH.
- No command execution, config edits, filesystem scanning, telemetry or network.
- Synthetic-input tests cover privacy, malicious metacharacters, empty boundaries and exit behavior.

Run: python3 tildeguard. Requires Python 3.9+ on macOS or Linux. This is not a full PATH safety audit and does not measure user outcomes.
