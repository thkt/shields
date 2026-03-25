[English](README.md) | **日本語**

# shields

Claude Code用セキュリティhook。危険なコマンドのブロックとファイルアクセス制御を1つのRustバイナリで提供します。

## 特徴

- **44のビルトインパターン**: 危険なコマンドをブロック（rm, eval, git push, curl|bash, リバースシェル, SQL drop等）
- **N1-N7正規化**: バイパス手法を無効化 — クォート除去、IFS展開、ブレース展開、ANSI-C hex/octalデコード
- **シークレット検出**: 機密ファイル（.env, .key, .pem, SSH鍵）がステージされた状態での`git commit`をブロック
- **ファイルACL**: エージェント種別で判定を分岐 — サブエージェントはhooks/settings/CLAUDE.mdへのアクセス拒否
- **パストラバーサル防止**: `Path::components()`による`..`コンポーネント検出
- **フェイルクローズド設計**: 不正入力・パースエラー・無効な設定 → block/deny（通過しない）
- **設定で拡張可能**: `.claude/tools.json`でカスタムパターン・シークレット・safe_dirsを追加

## 仕組み

### `shields check`（PreToolUse → Bash）

```text
stdin JSON → コマンド解析
  ├─ 改行をスペースに統合
  ├─ 正規化（N7 → N5 → N1 → N2 → N3 → N4 → N6）
  ├─ 元コマンド + 正規化後を44のビルトインパターンでマッチ
  ├─ tools.jsonのカスタムパターンでマッチ
  ├─ git commitの場合 → ステージファイルを20のシークレットパターンで検査
  └─ マッチ → block（stdout JSON + stderrログ）
     マッチなし → exit 0（通過）
```

### `shields acl`（PermissionRequest）

優先順序: deny > ask > approve

```text
stdin JSON → file_path, tool_name, agent_id を解析
  ├─ パストラバーサル（..） → deny
  ├─ サブエージェント + hooks/settings/CLAUDE.md → deny
  ├─ 機密ファイル（.env, .key, SSH鍵） → 書き込みdeny / 読み取りask
  ├─ セキュリティ重要な.claude/パス → ask
  ├─ 全hooks → ask
  ├─ システムプロンプトディレクトリ（memory, projects） → ask
  ├─ 安全なデータディレクトリ（workspace, logs, cache） → approve
  ├─ その他の.claude/パス → ask
  └─ それ以外 → ask
```

## ブロックパターン

### コマンドガード

| カテゴリ           | 例                                                | 数 |
| ------------------ | ------------------------------------------------- | -- |
| ファイル削除       | `rm -rf`, `rmdir`, `unlink`, `shred`              | 5  |
| リモートコード実行 | `curl \| bash`, `wget \| sh`, `source <(`         | 4  |
| 破壊的git操作      | `git push`, `reset --hard`, `clean -fd`           | 6  |
| 間接的削除         | `xargs rm`, `find -exec rm`, `find -delete`       | 3  |
| 間接的実行         | `eval`, `sed -i`, `awk system()`                  | 4  |
| ダウンロード＆実行 | `curl -o /tmp`, `wget -O /tmp`                    | 2  |
| インタプリタ迂回   | `python -c`, `node -e`, `perl -e`, `php -r`       | 9  |
| データ窃取         | `nc`, `scp`, `curl -T`, `rsync user@host:`        | 6  |
| リバースシェル     | `bash -i >& /dev/tcp/`, `mkfifo`                 | 2  |
| SQL破壊            | `DROP TABLE`, `TRUNCATE`                          | 2  |
| GitHub成りすまし   | `gh pr comment`, `gh issue comment`               | 1  |

### 正規化（N1-N7）

各変換には`contains`ガードがあり、通常のコマンドではアロケーションをスキップします。

| ID | 変換               | 変換前                | 変換後      |
| -- | ------------------- | --------------------- | ----------- |
| N1 | クォート除去        | `'rm' -rf /`          | `rm -rf /`  |
| N2 | コマンド置換除去    | `$(rm -rf /)`         | `rm -rf /)` |
| N3 | IFS展開除去         | `rm${IFS}-rf`         | `rm -rf`    |
| N4 | ブレース展開除去    | `{rm,-rf,/}`          | `rm -rf /`  |
| N5 | 変数間接参照除去    | `${!var}`             | `${var}`    |
| N6 | バックスラッシュ除去 | `r\m -rf`             | `rm -rf`    |
| N7 | ANSI-Cデコード      | `$'\x72\x6d' -rf /`  | `rm -rf /`  |

N7はhex（`\xNN`）とoctal（`\NNN`）の両方に対応しています。

### シークレット検出

以下の20のビルトインパターンにマッチするファイルがステージされた状態での`git commit`をブロックします。

`.env`, `.env.local`, `.env.production`, `.key`, `.pem`, `.p12`, `.pfx`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `.secret`, `.token`, `credentials.json`, `service_account.json`, `.keystore`, `.jks`, `.htpasswd`, `.netrc`, `.npmrc`, `.pypirc`

## インストール

### Claude Code Plugin（推奨）

バイナリのインストールとhookの登録が自動で行われます。

```bash
claude plugins marketplace add thkt/sentinels
claude plugins install shields
```

### Homebrew

```bash
brew install thkt/tap/shields
```

### リリースバイナリから

[Releases](https://github.com/thkt/shields/releases)から最新バイナリをダウンロードしてください。

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/shields/releases/latest/download/shields-aarch64-apple-darwin.tar.gz | tar xz
mv shields ~/.local/bin/
```

### ソースから

```bash
git clone https://github.com/thkt/shields.git
cd shields
cargo build --release
cp target/release/shields ~/.local/bin/
```

## 使い方

### Claude Code Pluginとして

sentinelsマーケットプレース経由でインストールすると、hookが自動的に登録されます。手動設定は不要です。

### 手動Hook設定

`~/.claude/settings.json`に追加してください。

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

## 終了コード

| コード | 意味                                                    |
| ------ | ------------------------------------------------------- |
| 0      | 通過（出力なし）またはブロック（stdoutにJSON出力）      |
| 2      | フォールバックblock/deny（JSON出力失敗時、stderrのみ） |

hookプロトコルではstdout JSONで判定を返します。出力なしのexit 0 = 承認。

## 設定

プロジェクトルートの`.claude/tools.json`に`shields`キーを追加します。全フィールドはオプション — デフォルトではビルトインパターンのみで全ガードが有効です。

### スキーマ

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

| キー               | 型           | デフォルト | 説明                                           |
| ------------------ | ------------ | ---------- | ---------------------------------------------- |
| `check`            | bool         | `true`     | コマンドガードの有効化（PreToolUse Bash）       |
| `acl`              | bool         | `true`     | ファイルACLの有効化（PermissionRequest）        |
| `custom_patterns`  | PatternDef[] | `[]`       | 追加のコマンドブロックパターン（ビルトインに追加） |
| `secrets_patterns` | string[]     | `[]`       | 追加のシークレット検出パターン（ビルトインに追加） |
| `safe_dirs`        | string[]     | `[]`       | `.claude/`配下の自動承認ディレクトリ追加        |
| `deny_subagent`    | string[]     | `[]`       | `.claude/`配下のサブエージェント拒否パス追加    |

### PatternDef

```json
{
  "id": "kubectl-delete",
  "regex": "\\bkubectl\\s+delete\\b",
  "context": "kubectl deleteは禁止されています。ユーザーに確認してください。"
}
```

### 設定例

**カスタムコマンドブロックの追加**:

```json
{
  "shields": {
    "custom_patterns": [
      {
        "id": "terraform-destroy",
        "regex": "\\bterraform\\s+destroy\\b",
        "context": "terraform destroyは禁止されています。ユーザーに確認してください。"
      }
    ]
  }
}
```

**`.tfstate`ファイルのコミットをブロック**:

```json
{
  "shields": {
    "secrets_patterns": ["\\.tfstate$"]
  }
}
```

**カスタム`.claude/`ディレクトリの自動承認**:

```json
{
  "shields": {
    "safe_dirs": ["custom-data"]
  }
}
```

### バリデーション

| 入力                            | 動作                                               |
| ------------------------------- | -------------------------------------------------- |
| カスタムパターンの不正regex     | shields全体がブロック（フェイルクローズド）         |
| safe_dirsの絶対パス             | 無視される（Path::joinバイパス防止のため）         |
| 設定パスのパストラバーサル      | 無視される                                         |
| tools.jsonなし                  | ビルトインパターンのみで全ガード有効               |
| tools.jsonの不正JSON            | ビルトインパターンのみで全ガード有効               |

### 設定ファイルの解決

設定ファイルはカレントディレクトリの`.claude/tools.json`から読み込まれます。

```text
project-root/
├── .claude/
│   └── tools.json     ← {"shields": {"custom_patterns": [...]}}
├── .git/
└── src/
```

## 関連ツール

Claude Code向け品質パイプラインの一部です。各ツールは異なるフェーズを担当します。フルスイートをインストールすると包括的なカバレッジが得られます。

```bash
brew install thkt/tap/shields thkt/tap/guardrails thkt/tap/formatter thkt/tap/reviews thkt/tap/gates
```

| ツール                                           | Hook                           | 役割                          |
| ------------------------------------------------ | ------------------------------ | ----------------------------- |
| **shields**                                      | PreToolUse + PermissionRequest | コマンドガード + ファイルACL  |
| [guardrails](https://github.com/thkt/guardrails) | PreToolUse                     | リント + セキュリティチェック |
| [formatter](https://github.com/thkt/formatter)   | PostToolUse                    | 自動コード整形                |
| [reviews](https://github.com/thkt/reviews)       | PreToolUse                     | 静的解析コンテキスト提供      |
| [gates](https://github.com/thkt/gates)           | Stop                           | 品質ゲート + レビュー強制     |

セットアップの詳細は [thkt/tap](https://github.com/thkt/homebrew-tap) を参照してください。

## ライセンス

MIT
