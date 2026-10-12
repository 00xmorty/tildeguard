# TildeGuard

Why does a command work only in some directories? TildeGuard flags literal leading tildes, empty entries and other relative entries in the POSIX PATH inherited by its process. Reports show entry numbers and categories, never your PATH values.

Dependency-free Python 3.9+; macOS and Linux. This is a narrowly scoped explainer, not a shell configuration editor or a complete PATH auditor.

## Run

From the repository:

```sh
git clone https://github.com/00xmorty/tildeguard.git
cd tildeguard
python3 tildeguard
python3 tildeguard --json --check
```

Or download the single-file release asset, inspect it, and run `python3 tildeguard`. No package install or sudo needed. If PATH cannot locate Python, use the absolute path of a trusted Python interpreter already installed on your machine. The executable shebang itself needs a working PATH to find Python.

### Safe demonstration

Run a separate child process with a synthetic PATH; this does not modify your shell configuration:

```sh
PATH='~/.local/bin::/usr/bin:/bin' /usr/bin/python3 tildeguard --json --check
```

On systems without `/usr/bin/python3`, substitute your trusted interpreter's absolute path. Expected output (exit code 1):

```json
{"entry_count": 4, "findings": [{"cwd_dependent": true, "entry": 1, "kind": "literal_home_tilde"}, {"cwd_dependent": true, "entry": 2, "kind": "empty"}], "schema_version": 1, "status": "REVIEW"}
```

## Interpreting findings

- `literal_home_tilde`: `~` or `~/...` survived into PATH. Review the relevant configuration line. An example is `"$HOME/.local/bin"` instead of `"~/.local/bin"`; the tool never generates or applies a patch.
- `literal_other_tilde`: another leading tilde, such as `~someone`; intended expansion requires manual review, not blind replacement.
- `empty`: an empty colon-delimited entry refers to the current directory.
- `relative`: another non-absolute entry; its interpretation depends on the current directory. This can be intentional.

Entry positions are 1-based and include all entries, including empty ones. A tilde embedded in an absolute path is not flagged.

Default advisory mode exits 0 even with findings or unknown input. With `--check`: 0 = NO_FINDINGS, 1 = REVIEW, 2 = UNKNOWN (PATH absent). A present empty PATH is REVIEW, not absent. Invalid command-line arguments also exit 2 with argparse diagnostics.

## Safety

Read-only environment inspection. No filesystem traversal, shell execution, subprocesses, config reads/writes, repair, sudo, telemetry or network access. Only PATH is analyzed; values, usernames and directory names are never echoed. Metacharacters and terminal control characters in PATH are never evaluated or displayed. Diagnostics never claim that a directory is safe to delete or that a configuration must be changed.

## Limitations

- POSIX colon-delimited PATH only; not Windows PATH.
- Inspects the environment of this process, not every shell, GUI app or unexported zsh `path` array. It cannot reconstruct the quoting in the original configuration.
- Does not test existence, ownership, permissions, symlinks, command shadowing, executability or whether a command can actually run. NO_FINDINGS is not a safety certification.
- Shell expansion depends on context and options. Read the [official zsh expansion documentation](https://zsh.sourceforge.io/Doc/Release/Expansion.html#Filename-Expansion) before editing config.
- Relative entries can be intentional. Entry-number reports still reveal structural counts; review any report before sharing.
- There is no measured user outcome, payment intent or revenue evidence for this tool.

## Test

```sh
python3 -m py_compile tildeguard
python3 -m unittest discover -s tests -v
```

MIT license. See SECURITY.md for responsible reporting.
