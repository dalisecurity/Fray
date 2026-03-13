# Fray — WAFバイパス & セキュリティテストツールキット

**🌐 Language:** [English](README.md) | **日本語**

### ⚔️ *オープンソースWAFバイパスツールキット — 情報収集、スキャン、バイパス、堅牢化。依存関係ゼロ。*

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/DaliSecurity.fray-security?label=VS%20Code&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)
[![Docs](https://img.shields.io/badge/Docs-dalisec.io-6366f1)](https://dalisec.io/docs/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> **正規の許可を得たセキュリティテスト専用** — 自身が所有する、または書面で明示的に許可を得たシステムのみテストしてください。

Frayは[wafw00f](https://github.com/EnableSecurity/wafw00f)（検出）と[sqlmap](https://github.com/sqlmapproject/sqlmap)（攻撃）の間を埋めるツール — 完全な**情報収集 → バイパス → 堅牢化**パイプラインを1つの `pip install` で提供します。

## 最新アップデート

**v3.4 — 2026年3月**
- **GitHub Action** — PR毎にWAFをテスト（`uses: dalisecurity/fray@v1`）
- **MCPサーバー** — Claude Code & ChatGPT連携（`pip install fray[mcp]`）
- **35項目リコン** — TLS、CORS、VPNゲートウェイ、AI/LLMエンドポイント、クラウドバケット、シークレット
- **6つのディープスキャンモジュール** — XSS、SQLi、CMDi、キャッシュポイズニング、マスアサイン、デシリアライゼーション
- **インタラクティブメニュー** — 検出結果から次のステップを自動提案

**開発中：** レースコンディションテスト · WAFルールリバースエンジニアリング · バッチリコン · 自然言語クエリ
→ [全変更履歴](CHANGELOG.md)

---

## なぜFray？

- **オールインワン** — 情報収集、スキャン、バイパス、堅牢化、ファジング、レポートを1つのツールで
- **スマート** — アダプティブキャッシュがドメイン間で学習。ブロック済みペイロードは再送しない
- **依存関係ゼロ** — Python標準ライブラリのみ。`pip install fray` ですぐ使える
- **4,000以上のペイロード** — 23カテゴリ、175件のCVE、ライブ脅威フィードから継続更新

---

## クイックスタート

```bash
pip install fray
```

```bash
fray recon https://target.com          # 35項目の情報収集
fray test https://target.com --smart   # リコン結果からスマートにペイロード選択
fray detect https://target.com         # WAF/CDNベンダーを特定（98社対応）
fray auto https://target.com           # フルパイプライン：recon → scan → bypass
fray fuzz https://target.com/FUZZ      # コンテンツ探索（ffuf互換）
fray harden https://target.com         # OWASP堅牢化監査（A-Fグレード）
```

<p align="center">
  <img src="docs/demo.gif" alt="Frayデモ — WAF検出とXSSバイパス" width="720">
</p>

---

## コアコマンド

### `fray recon` — 情報収集

1コマンドで35以上のチェック：TLS、DNS、サブドメイン、CORS、セキュリティヘッダー、管理画面、VPNゲートウェイ、AI/LLMエンドポイント、クラウドバケット、シークレット、JSエンドポイント抽出など。JSON、HTMLレポート、またはインタラクティブメニューで出力。

```bash
fray recon https://target.com --deep   # サブドメインブルートフォース付きフルスキャン
```

### `fray test --smart` — 脆弱性テスト

リコン結果を読み取り、適切なペイロードを自動選択。6つのディープモジュール：`XSSScanner`、`SQLiInjector`、`CMDiScanner`、`CachePoisonScanner`、`MassAssignScanner`、`DeserScanner`。

```bash
fray test https://target.com --smart -c xss   # コンテキスト認識XSSテスト
```

### `fray detect` — WAFフィンガープリント

ヘッダー、CNAMEレコード、Cookie、レスポンスシグネチャから98社のWAF/CDNベンダーを特定。

```bash
fray detect https://target.com --json
```

### `fray report` — レポート

スキャン結果からHTMLまたはMarkdownレポートを生成。統一v11ダークテーマ。

```bash
fray report --company example.com -o report.md
```

[全コマンド →](docs/quickstart.md) · [スキャンガイド →](docs/scanning-guide.md)

---

## 認証 & ステルス

```bash
fray test https://target.com --cookie "session=abc123"     # Cookie認証
fray test https://target.com --bearer eyJhbG...             # Bearerトークン
fray test https://target.com --stealth -d 0.5               # UA回転 + ジッター
fray recon https://target.com --scope scope.txt             # スコープ制限
```

セッションプロファイル、OAuth2クライアントクレデンシャル、マルチステップフォームログインにも対応。[認証ガイド →](docs/authentication-guide.md)

---

## CI/CD

```yaml
# .github/workflows/waf.yml
- uses: dalisecurity/fray@v1
  with:
    target: https://staging.example.com
    categories: xss,sqli
```

バイパス検出時にnon-zeroで終了。SARIF経由でGitHub Security tabに統合。`--json` でパイプライン連携。[CI/CDガイド →](docs/github-action-guide.md)

---

## ペイロードカバレッジ

4,000以上のペイロード、23カテゴリ、175件のCVE（2020-2026）：

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS | 1,209 | SSRF | 122 |
| SQLインジェクション | 248 | SSTI | 122 |
| コマンドインジェクション | 200 | XXE | 84 |
| AI/LLMプロンプトインジェクション | 370 | パストラバーサル | 109 |
| モダンバイパス | 137 | CSPバイパス | 104 |
| APIセキュリティ | 130 | プロトタイプ汚染 | 110 |

[ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md)

---

## MCPサーバー — AIエージェント連携

Frayは[MCP](https://modelcontextprotocol.io/)経由で14ツールを提供。Claude、ChatGPT、Cursorなどから利用可能。

```bash
pip install 'fray[mcp]'
```

```json
{ "mcpServers": { "fray": { "command": "python", "args": ["-m", "fray.mcp_server"] } } }
```

*「CloudflareをバイパスするXSSペイロードは？」* と聞くと、Frayのツール（`suggest_payloads_for_waf`、`generate_bypass_strategy`、`search_payloads`、`analyze_response`、`hardening_check`、[他9ツール](docs/claude-code-guide.md)）が直接呼び出されます。

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md)

---

## VS Code拡張機能

[![インストール](https://img.shields.io/badge/Install-VS%20Code%20Marketplace-007ACC?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)

11コマンド、右クリックスキャン、インライン診断、HTMLレポートパネル（`Cmd+Shift+R`）、アクティビティバーサイドバー。[拡張機能ドキュメント →](vscode-fray/README.md)

---

## ドキュメント & リンク

**[📖 ドキュメント](docs/)** · **[クイックスタート](docs/quickstart.md)** · **[PyPI](https://pypi.org/project/fray/)** · **[Issues](https://github.com/dalisecurity/fray/issues)** · **[Discussions](https://github.com/dalisecurity/fray/discussions)**

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。AIコーディングエージェントは [AGENTS.md](AGENTS.md) を参照。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

<!-- mcp-name: io.github.dalisecurity/fray -->
