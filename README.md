**English** | [日本語](README.ja.md)

# shields

Security hook for Claude Code. Blocks dangerous commands and controls file access with a single Rust binary.

## Features

- **44 builtin patterns**: Blocks dangerous commands (rm, eval, git push, curl|bash, reverse shells, SQL drops...)
- **N1-N7 normalization**: Defeats bypass techniques — quote stripping, IFS expansion, brace expansion, ANSI-C hex/octal decode
- **Secrets detection**: Blocks `git commit` when sensitive files (.env, .key, .pem, SSH keys) are staged
- **File ACL**: Agent-type branching — subagents denied from hooks, settings, CLAUDE.md; main agents prompted
- **Path traversal protection**: Rejects `..` components via `Path::components()` analysis
- **Fail-closed**: Malformed input, parse errors, invalid config → block/deny (never silent pass)
- **Config extensible**: Custom patterns, secrets, safe_dirs via `.claude/tools.json`

## How It Works

### `shields check` (PreToolUse → Bash)

```text
stdin JSON → parse command
  ├─ Collapse newlines
  ├─ Normalize (N7 → N5 → N1 → N2 → N3 → N4 → N6)
  ├─ Match original + normalized against 44 builtin patterns
  ├─ Match against custom patterns from tools.json
  ├─ If git commit → check staged files against 20 secret patterns
  └─ Match → block (JSON stdout + stderr log)
     No match → exit 0 (pass through)
```

### `shields acl` (PermissionRequest)

Priority order: deny > ask > approve.

```text
stdin JSON → parse file_path, tool_name, agent_id
  ├─ Path traversal (..) → deny
  ├─ Subagent + hooks/settings/CLAUDE.md → deny
  ├─ Sensitive files (.env, .key, SSH keys) → deny writes / ask reads
  ├─ Security-critical .claude/ paths → ask
  ├─ All hooks → ask
  ├─ System prompt dirs (memory, projects) → ask
  ├─ Safe data dirs (workspace, logs, cache) → approve
  ├─ Other .claude/ paths → ask
  └─ Everything else → ask
```

## Blocked Patterns

### Command Guard

| Category              | Examples                                       | Count |
| --------------------- | ---------------------------------------------- | ----- |
| File deletion         | `rm -rf`, `rmdir`, `unlink`, `shred`           | 5     |
| Remote code execution | `curl \| bash`, `wget \| sh`, `source <(`      | 4     |
| Destructive git       | `git push`, `reset --hard`, `clean -fd`        | 6     |
| Indirect deletion     | `xargs rm`, `find -exec rm`, `find -delete`    | 3     |
| Indirect execution    | `eval`, `sed -i`, `awk system()`               | 4     |
| Download-then-execute | `curl -o /tmp`, `wget -O /tmp`                 | 2     |
| Interpreter bypass    | `python -c`, `node -e`, `perl -e`, `php -r`    | 9     |
| Data exfiltration     | `nc`, `scp`, `curl -T`, `rsync user@host:`     | 6     |
| Reverse shell         | `bash -i >& /dev/tcp/`, `mkfifo`              | 2     |
| SQL destruction       | `DROP TABLE`, `TRUNCATE`                       | 2     |
| GitHub impersonation  | `gh pr comment`, `gh issue comment`            | 1     |

### Normalization (N1-N7)

Each transform has a `contains` guard — clean commands skip all allocations.

| ID | Transform         | Before               | After      |
| -- | ----------------- | -------------------- | ---------- |
| N1 | Quote removal     | `'rm' -rf /`         | `rm -rf /` |
| N2 | Command sub       | `$(rm -rf /)`        | `rm -rf /` |
| N3 | IFS expansion     | `rm${IFS}-rf`        | `rm -rf`   |
| N4 | Brace expansion   | `{rm,-rf,/}`         | `rm -rf /` |
| N5 | Var indirection   | `${!var}`            | `${var}`   |
| N6 | Backslash removal | `r\m -rf`            | `rm -rf`   |
| N7 | ANSI-C decode     | `$'\x72\x6d' -rf /` | `rm -rf /` |

N7 handles both hex (`\xNN`) and octal (`\NNN`) escapes.

### Secrets Detection

Blocks `git commit` when any staged file matches these 20 builtin patterns:

`.env`, `.env.local`, `.env.production`, `.key`, `.pem`, `.p12`, `.pfx`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `.secret`, `.token`, `credentials.json`, `service_account.json`, `.keystore`, `.jks`, `.htpasswd`, `.netrc`, `.npmrc`, `.pypirc`

## Installation

### Claude Code Plugin (recommended)

Installs the binary and registers hooks automatically:

```bash
claude plugins marketplace add github:thkt/sentinels
claude plugins install shields
```

### Homebrew

```bash
brew install thkt/tap/shields
```

### From Release

Download the latest binary from [Releases](https://github.com/thkt/shields/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/shields/releases/latest/download/shields-aarch64-apple-darwin.tar.gz | tar xz
mv shields ~/.local/bin/
```

### From Source

```bash
git clone https://github.com/thkt/shields.git
cd shields
cargo build --release
cp target/release/shields ~/.local/bin/
```

## Usage

### As Claude Code Plugin

When installed via the sentinels marketplace, hooks are registered automatically. No manual setup needed.

### Manual Hook Setup

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "shields check",
            "timeout": 2000
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "shields acl",
            "timeout": 2000
          }
        ]
      }
    ]
  }
}
```

## Exit Codes

| Code | Meaning                                                |
| ---- | ------------------------------------------------------ |
| 0    | Passed (no output) or blocked (JSON on stdout)         |
| 2    | Fallback block/deny (stderr only, when JSON fails)     |

The hook protocol uses stdout JSON for decisions. Exit 0 with no output = approved.

## Configuration

Add a `shields` key to `.claude/tools.json` in your project root. All fields are optional — defaults enable all guards with builtin patterns only.

### Schema

```json
{
  "shields": {
    "check": true,
    "acl": true,
    "custom_patterns": [],
    "secrets_patterns": [],
    "safe_dirs": [],
    "deny_subagent": []
  }
}
```

| Key                | Type         | Default | Description                                          |
| ------------------ | ------------ | ------- | ---------------------------------------------------- |
| `check`            | bool         | `true`  | Enable command guard (PreToolUse Bash)                |
| `acl`              | bool         | `true`  | Enable file ACL (PermissionRequest)                  |
| `custom_patterns`  | PatternDef[] | `[]`    | Additional command block patterns (merged w/ builtin) |
| `secrets_patterns` | string[]     | `[]`    | Additional regex for secrets check (merged w/ builtin) |
| `safe_dirs`        | string[]     | `[]`    | Extra `.claude/` subdirs to auto-approve             |
| `deny_subagent`    | string[]     | `[]`    | Extra `.claude/` paths to deny for subagents         |

### PatternDef

```json
{
  "id": "kubectl-delete",
  "regex": "\\bkubectl\\s+delete\\b",
  "context": "kubectl delete is prohibited. Ask the user."
}
```

### Examples

**Add a custom command block**:

```json
{
  "shields": {
    "custom_patterns": [
      {
        "id": "terraform-destroy",
        "regex": "\\bterraform\\s+destroy\\b",
        "context": "terraform destroy is prohibited. Ask the user."
      }
    ]
  }
}
```

**Block `.tfstate` files from being committed**:

```json
{
  "shields": {
    "secrets_patterns": ["\\.tfstate$"]
  }
}
```

**Auto-approve a custom `.claude/` directory**:

```json
{
  "shields": {
    "safe_dirs": ["custom-data"]
  }
}
```

### Validation

| Input                           | Behavior                                        |
| ------------------------------- | ----------------------------------------------- |
| Invalid regex in custom pattern | shields blocks everything (fail-closed)         |
| Absolute path in safe_dirs      | Silently rejected (security: prevents Path::join bypass) |
| Path traversal in config paths  | Silently rejected                               |
| Missing tools.json              | All guards enabled with builtin patterns only   |
| Malformed tools.json            | All guards enabled with builtin patterns only   |

### Config Resolution

Config is read from `.claude/tools.json` in the current working directory.

```text
project-root/
├── .claude/
│   └── tools.json     ← {"shields": {"custom_patterns": [...]}}
├── .git/
└── src/
```

## Companion Tools

This tool is part of a quality pipeline for Claude Code. Each covers a different
phase — install the full suite for comprehensive coverage:

```bash
brew install thkt/tap/shields thkt/tap/guardrails thkt/tap/formatter thkt/tap/reviews thkt/tap/gates
```

| Tool                                             | Hook                           | Role                              |
| ------------------------------------------------ | ------------------------------ | --------------------------------- |
| **shields**                                      | PreToolUse + PermissionRequest | Command guard + file ACL          |
| [guardrails](https://github.com/thkt/guardrails) | PreToolUse                     | Lint + security on Write/Edit     |
| [formatter](https://github.com/thkt/formatter)   | PostToolUse                    | Auto code formatting              |
| [reviews](https://github.com/thkt/reviews)       | PreToolUse                     | Static analysis context injection |
| [gates](https://github.com/thkt/gates)           | Stop                           | Quality gates + review            |

See [thkt/tap](https://github.com/thkt/homebrew-tap) for setup details.

## License

MIT
