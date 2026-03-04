# Fray

### ⚔️ *オープンソースWAFセキュリティテストツールキット — 情報収集、検出、テスト、レポート*

[![Payloads](https://img.shields.io/badge/ペイロード-5500+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF検出-25社+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/情報収集チェック-14項目-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![OWASP](https://img.shields.io/badge/OWASP-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/fray)

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

**🌐 Language:** [English](README.md) | **日本語**

> ⚠️ **正規の許可を得たセキュリティテスト専用** — 自身が所有する、または書面で明示的に許可を得たシステムのみテストしてください。

---

## なぜ Fray？

多くのペイロード集は静的なテキストファイルに過ぎません。Frayなら**一気通貫のワークフロー**で完結します — 情報収集 → 検出 → テスト → レポート：

- 🔍 **情報収集** — 14項目のチェック：TLS、ヘッダー、Cookie、DNS、CORS、公開ファイル、サブドメイン
- 🎯 **スマートテスト** — WordPressを検出したら sqli + xss ペイロードを自動推奨。Y/Nで選択
- 🛡️ **WAF検出** — 25社のベンダーをフィンガープリント（Cloudflare、AWS、Akamai、Imperva等）
- 🐛 **HackerOne対応** — 構造化されたJSON出力がHackerOneの脆弱性分類にそのまま対応
- 🤖 **AI対応** — Claude Code・ChatGPT連携用MCPサーバー搭載
- 📊 **ワンコマンドレポート** — HTML・Markdownで脆弱性分析レポートを生成
- ⚡ **依存関係ゼロ** — Python標準ライブラリのみで動作。`pip install fray` ですぐ使える

| OWASPフレームワーク | ペイロード数 | カバレッジ |
|-------------------|-----------|----------|
| **Web Top 10:2021** | 1,690+ | ✅ 100% |
| **Mobile Top 10:2024** | 575+ | ✅ 100% |
| **LLM Top 10**（AI/ML） | 300+ | ✅ 100% |
| **API Security Top 10** | 520+ | ✅ 100% |

**対象ユーザー：** バグバウンティハンター · レッドチーム・ペンテスター · セキュリティ研究者 · WAF設定を検証するブルーチーム · セキュリティを学ぶ学生

---

## クイックスタート

```bash
pip install fray
```

```bash
# 1. 情報収集 — テスト前にターゲットを把握
fray recon https://example.com

# 2. スマートモード — 情報収集 + 対話的にペイロードを選択
fray test https://example.com --smart

# 3. WAFベンダーの検出
fray detect https://example.com

# 4. 特定カテゴリでテスト
fray test https://example.com -c xss --max 10

# 5. レポート生成
fray report -i results.json -o report.html
```

---

## 🔍 情報収集 — `fray recon`

14項目の自動チェックをワンコマンドで実行：

```bash
fray recon https://example.com
```

| チェック項目 | 検出内容 |
|------------|---------|
| **TLS** | バージョン、暗号スイート、証明書の有効期限、TLS 1.0/1.1 |
| **セキュリティヘッダー** | HSTS、CSP、X-Frame-Options + 他6項目（スコア付き） |
| **Cookie** | HttpOnly、Secure、SameSiteフラグ（スコア付き） |
| **フィンガープリント** | WordPress、Drupal、PHP、Node.js、React、nginx、Apache、Java、.NET等 |
| **DNS** | A/AAAA/CNAME/MX/TXT/NSレコード、CDN検出、SPF/DMARC |
| **robots.txt** | 制限パス、注目すべきエンドポイント（admin、api、login） |
| **CORS** | ワイルドカードオリジン、反射型オリジン、認証情報の設定不備 |
| **公開ファイル** | 28パスをプローブ — `.env`、`.git`、phpinfo、actuator、SQLダンプ |
| **HTTPメソッド** | 危険なメソッド：PUT、DELETE、TRACE |
| **エラーページ** | スタックトレース、バージョンリーク、フレームワーク情報の404分析 |
| **サブドメイン** | crt.sh証明書透明性ログによる列挙 |

```bash
fray recon https://example.com --json       # JSON出力
fray recon https://example.com -o recon.json # ファイルに保存
```

> 📖 詳細は [docs/quickstart.md](docs/quickstart.md) を参照

---

## 🎯 スマートモード — `fray test --smart`

情報収集を先に実行し、検出結果に基づき最適なペイロードを提案：

```
🔍 Running reconnaissance on https://example.com...

───────────────────────────────────────────────────
  Target:  https://example.com
  TLS:     TLSv1.3
  Headers: 67%
  Stack:   wordpress (100%), nginx (70%)
───────────────────────────────────────────────────

  Recommended categories (based on detected stack):

    1. sqli                      (1200 payloads)
    2. xss                       (800 payloads)
    3. path_traversal            (400 payloads)

    Total: 2400 payloads (vs 5500 if all categories)

  [Y] Run recommended  [A] Run all  [N] Cancel  [1,3] Pick:
```

| 入力 | 動作 |
|-----|------|
| **Y** | 推奨カテゴリを実行 |
| **A** | 全カテゴリを実行 |
| **N** | キャンセル |
| **1,3** | 特定のカテゴリを選択 |

```bash
fray test https://example.com --smart -y    # 自動承認（CI/スクリプト用）
```

**検出技術 → ペイロードのマッピング：**

| 検出技術 | 優先ペイロード |
|---------|-------------|
| WordPress | sqli, xss, path_traversal, command_injection, ssrf |
| Drupal | sqli, ssti, xss, command_injection |
| PHP | sqli, path_traversal, command_injection, file_upload |
| Node.js | ssti, ssrf, xss, command_injection |
| Java | ssti, xxe, sqli, command_injection |
| .NET | sqli, path_traversal, xxe, command_injection |

> 📖 OWASPカバレッジの詳細は [docs/owasp-complete-coverage.md](docs/owasp-complete-coverage.md) を参照

---

## 🛡️ WAF検出 — 25社対応

```bash
fray detect https://example.com
```

対応ベンダー：**Cloudflare、AWS WAF、Akamai、Imperva、F5 BIG-IP、Fastly、Azure WAF、Google Cloud Armor、Sucuri、Fortinet、Wallarm、Vercel** 他13社

[全ベンダー一覧 + 検出シグネチャ →](docs/waf-detection-guide.md) · [WAFリサーチ →](docs/waf-detection-research.md)

---

## 🐛 バグバウンティ連携

Frayはバグバウンティのワークフローに最適化されています — 情報収集からレポート提出まで：

```bash
# フルワークフロー：情報収集 → スマートテスト → レポート
fray recon https://target.hackerone.com -o recon.json
fray test https://target.hackerone.com --smart -y -o results.json
fray report -i results.json -o report.html --format markdown
```

| プラットフォーム | Frayの活用方法 |
|---------------|-------------|
| **HackerOne** | 構造化された発見事項、Markdownレポート、脆弱性分類の整合 |
| **Bugcrowd** | JSON出力が提出テンプレートに対応 |
| **Intigriti** | 情報収集 → テスト → レポートのワークフロー |
| **YesWeHack** | 情報収集スコアからの重大度マッピング |

### ワークフロー例

```
1. fray recon https://target.com         → 攻撃対象面を調査
2. fray detect https://target.com        → WAFの種類を特定
3. fray test https://target.com --smart  → 優先度付きペイロードでテスト
4. fray report -i results.json           → 提出用レポートを生成
```

---

## 🤖 MCPサーバー — AI連携

```bash
pip install fray[mcp]
fray mcp
```

Claude Desktop設定（`~/Library/Application Support/Claude/claude_desktop_config.json`）に追加：

```json
{
  "mcpServers": {
    "fray": { "command": "python", "args": ["-m", "fray.mcp_server"] }
  }
}
```

**6つのツール：** `list_payload_categories`、`get_payloads`、`search_payloads`、`get_waf_signatures`、`get_cve_details`、`suggest_payloads_for_waf`

Claudeに質問：*「CloudflareをバイパスするXSSペイロードは？」* → MCPツールが直接呼び出されます。

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md)

---

## 📊 レポート

```bash
fray report --sample                           # デモレポート
fray report -i results.json -o report.html     # HTMLレポート
fray report -i results.json --format markdown  # Markdownレポート
```

![Fray サンプルレポート](docs/sample-report.png)

[レポートガイド →](docs/report-guide.md) · [POCシミュレーションガイド →](docs/poc-simulation-guide.md)

---

## 📦 5,500以上のペイロード

```bash
fray payloads  # 全カテゴリを一覧表示
```

| カテゴリ | ペイロード数 | カテゴリ | ペイロード数 |
|---------|-----------|---------|-----------|
| XSS | 867 | SSRF | 167 |
| SQLi | 456 | SSTI | 98 |
| コマンドインジェクション | 234 | XXE | 123 |
| パストラバーサル | 189 | ファイルアップロード | 70+ |
| AI/LLMプロンプトインジェクション | 370 | Webシェル | 160+ |
| OWASPモバイル | 575+ | CVEエクスプロイト | 220 |

**120件の実際のCVE**（2020–2026年）を含む：Log4Shell、Spring4Shell、ProxyShell等。

[全ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md) · [AIセキュリティ →](docs/ai-security-guide.md) · [モバイルセキュリティ →](docs/owasp-mobile-top10.md) · [APIセキュリティ →](docs/owasp-api-security.md)

---

## 🏗️ プロジェクト構成

```
fray/
├── fray/
│   ├── cli.py              # CLIエントリーポイント
│   ├── recon.py             # 14項目の情報収集エンジン
│   ├── detector.py          # WAF検出（25社対応）
│   ├── tester.py            # ペイロードテストエンジン
│   ├── evolve.py            # 適応型ペイロード進化
│   ├── reporter.py          # HTML + Markdownレポート
│   ├── mcp_server.py        # AI連携用MCPサーバー
│   └── payloads/            # 5,500以上のペイロード（22カテゴリ）
├── tests/                   # 330テスト
├── docs/                    # 28ガイド
└── pyproject.toml           # pip install fray
```

---

## 📈 ロードマップ

**完了：**
- [x] 14項目の情報収集機能（`fray recon`）
- [x] 対話型プロンプトによるスマートペイロード選択（`--smart`）
- [x] Cookie、CORS、公開ファイル、DNS、サブドメインスキャン
- [x] 適応型ペイロード進化
- [x] HTML + Markdownレポート生成
- [x] AI連携用MCPサーバー

**次のステップ：**
- [ ] 共有可能なレポートURL（一時ホスティングHTML）
- [ ] HackerOne API連携（自動送信）
- [ ] Webベースのレポートダッシュボード
- [ ] MLベースのペイロード有効性スコアリング
- [ ] マルチWAF比較テスト

---

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。ペイロードの追加、ツール改善、ドキュメントのPRを歓迎します。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。本ツールの悪用について著者は一切の責任を負いません。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 全ドキュメント（28ガイド）](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**
