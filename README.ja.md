# Fray

### ⚔️ *オープンソースWAFセキュリティテストツールキット — スキャン、検出、テスト、レポート*

[![Payloads](https://img.shields.io/badge/ペイロード-5500+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF検出-25社+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/情報収集チェック-21項目-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![OWASP](https://img.shields.io/badge/OWASP-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/fray)

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

**🌐 Language:** [English](README.md) | **日本語**

> **正規の許可を得たセキュリティテスト専用** — 自身が所有する、または書面で明示的に許可を得たシステムのみテストしてください。

---

## なぜ Fray？

多くのペイロード集は静的なテキストファイルに過ぎません。Frayは**一気通貫のワークフロー**です：

- **`fray scan`** — 自動クロール → パラメータ発見 → ペイロード注入（新機能）
- **`fray recon`** — 21項目の自動チェック（TLS、ヘッダー、DNS、パラメータ、JS、過去URL、GraphQL、API、Host注入、管理画面）
- **`fray detect`** — 25社のWAFベンダーをフィンガープリント
- **`fray test`** — 5,500以上のペイロード（24のOWASPカテゴリ、prototype pollution含む）
- **`fray report`** — HTML・Markdownレポート
- **依存関係ゼロ** — Python標準ライブラリのみ。`pip install fray` ですぐ使える

## 誰が使う？

- **バグバウンティハンター** — 隠れたパラメータ・古いエンドポイント発見、WAFバイパス、レポート作成
- **ペンテスター** — フルrecon＋自動スキャン、クライアント向けHTMLレポート
- **ブルーチーム** — WAFルール検証、設定変更後の回帰テスト
- **DevSecOps** — CI/CDパイプラインでWAFテスト、バイパス検出時にビルド失敗
- **セキュリティリサーチャー** — WAFバイパス発見、ペイロード投稿
- **学生** — インタラクティブCTFチュートリアル、攻撃手法をハンズオンで学習

---

## クイックスタート

```bash
pip install fray
```

```bash
fray demo                                        # 今すぐ試す — WAF検出 + XSSスキャン
fray scan https://example.com                    # 自動スキャン（クロール + 注入）
fray recon https://example.com                   # 情報収集
fray test https://example.com --smart            # スマートペイロードテスト
fray detect https://example.com                  # WAF検出
fray explain CVE-2021-44228                      # CVEインテリジェンス
fray report -i results.json -o report.html       # レポート生成
```

---

## デモ

`fray demo` がWAF検出、クロール、XSSペイロード注入を実行。`↩ REFLECTED` = レスポンス本文でペイロード確認。**28秒で9件のXSSバイパスを発見。**

![fray demo](docs/demo.gif)

---

## `fray scan` — 自動攻撃対象面マッピング

ワンコマンドで：ターゲットをクロール、注入ポイントを発見、ペイロードをテスト、結果をレポート。

```bash
fray scan https://example.com -c xss -m 3 -w 4
```

```
──────────────────── Crawling https://example.com ────────────────────
  [  1] https://example.com
  [  2] https://example.com/search
  [  3] https://example.com/guestbook.php
  ✓ Crawled 10 pages, found 7 injection points (3 forms, 1 JS endpoints)

──────────────────────── Payload Injection ───────────────────────────
  [1/7] POST /guestbook.php ?name= (form)
      BLOCKED   403 │ <script>alert(1)</script>
      PASSED    200 │ <img src=x onerror=alert(1)>    ↩ REFLECTED
  [2/7] GET  /search ?q= (form)
      BLOCKED   403 │ <script>alert(1)</script>
      PASSED    200 │ <img src=x onerror=alert(1)>    ↩ REFLECTED

╭──────────── Scan Summary ────────────╮
│ Total Tested      21                 │
│ Blocked           15  (71.4%)        │
│ Passed             6                 │
│ Reflected          4  ← confirmed    │
╰──────────────────────────────────────╯
```

反射型ペイロードは `↩ REFLECTED` でハイライト — ペイロードがレスポンス本文にそのまま含まれることで注入が確認されます。

**処理の流れ：**
1. **クロール** — BFS探索、同一オリジンリンクを追跡、`robots.txt` + `sitemap.xml`からシード
2. **発見** — URL、HTMLフォーム、JavaScript APIコールからパラメータを抽出
3. **注入** — 選択カテゴリのペイロードで各パラメータをテスト
4. **反射検出** — レスポンス本文にペイロードがそのまま含まれるか確認
5. **自動バックオフ** — 429レート制限を指数バックオフで処理

```bash
# スコープ制限付きスキャン（バグバウンティ向け）
fray scan https://target.com --scope scope.txt -w 4

# 認証付きスキャン + ステルスモード
fray scan https://app.target.com --cookie "session=abc" --stealth

# SQLiペイロードで深いスキャン
fray scan https://target.com -c sqli --depth 5 --max-pages 100

# CIパイプライン向けJSON出力
fray scan https://target.com --json -o results.json
```

[全スキャンオプション + 使用例 →](docs/scanning-guide.md)

---

## `fray recon` — 21項目の自動チェック

```bash
fray recon https://example.com
fray recon https://example.com --js       # JSエンドポイント抽出
fray recon https://example.com --history  # 過去URL発見
fray recon https://example.com --params   # パラメータブルートフォース
```

| チェック項目 | 検出内容 |
|------------|--------|
| **パラメータ発見** | クエリ文字列、フォーム入力、JS APIエンドポイント |
| **パラメータマイニング** | 136個の一般的なパラメータ名をブルートフォース、隠れた`?id=`、`?file=`、`?redirect=`を検出 |
| **JSエンドポイント抽出** | LinkFinder型：隠しAPI、ホスト名、クラウドバケット（S3/GCS/Azure）、APIキー、シークレット |
| **過去URL発見** | Wayback Machine、sitemap.xml、robots.txtから古いエンドポイントを取得 |
| **GraphQLイントロスペクション** | 10個の一般的なエンドポイントをプローブ、スキーマ公開（型、フィールド、ミューテーション）を検出 |
| **API発見** | Swagger/OpenAPIスペック、`/api/v1/`、`/api-docs`、ヘルスエンドポイント — 全ルートとパラメータを露出 |
| **Hostヘッダーインジェクション** | パスワードリセット汚染、キャッシュポイズニング、`Host:` / `X-Forwarded-Host` 操作によるSSRF |
| **管理画面発見** | 70パス: `/admin`、`/wp-admin`、`/phpmyadmin`、`/actuator`、`/console`、デバッグツール |
| **TLS** | バージョン、暗号スイート、証明書有効期限 |
| **セキュリティヘッダー** | HSTS、CSP、X-Frame-Options（スコア付き） |
| **Cookie** | HttpOnly、Secure、SameSiteフラグ |
| **フィンガープリント** | WordPress、PHP、Node.js、nginx、Apache、Java、.NET |
| **DNS** | A/CNAME/MX/TXT、CDN検出、SPF/DMARC |
| **CORS** | ワイルドカード、反射型オリジン、認証情報の設定不備 |

その他：28件の公開ファイルプローブ（`.env`、`.git`、phpinfo、actuator）· crt.sh経由のサブドメイン列挙

`--js` はインラインおよび外部JavaScriptファイルをLinkFinder型で解析 — `fetch()`、`axios`、`XMLHttpRequest` 呼び出し、完全URL、内部ホスト名/サブドメイン、クラウドストレージバケット（AWS S3、GCS、Azure Blob、Firebase、DO Spaces）、漏洩シークレット（AWSキー、Google APIキー、GitHubトークン、Stripeキー、Slack Webhook、JWT、Bearerトークン、汎用APIキー）。

`--history` はWayback Machine CDX API、sitemap.xml、robots.txt Disallowパスを検索。古いエンドポイントはWAFルールが弱いことが多いです。

`--params` は136個の一般的なパラメータ名をブルートフォース。レスポンス差分（ステータス、サイズ、反射）で隠れたパラメータを検出。リスク評価：HIGH（SSRF/LFI/インジェクション）、MEDIUM（XSS/IDOR）。

GraphQLイントロスペクションはフルrecon時に自動実行。`/graphql`、`/api/graphql`、`/v1/graphql`、`/graphiql`、`/playground`等をプローブします。

API発見は30以上の一般的なパスをプローブ：`swagger.json`、`openapi.json`、`/api-docs`、`/swagger-ui/`、バージョン付きAPIルート。スペックを解析して全エンドポイント、メソッド、認証方式を抽出します。

**Fray初めて？** `fray help` で全コマンドのガイドを表示。

[情報収集ガイド →](docs/quickstart.md)

---

## `fray test --smart` — 適応型ペイロード選択

情報収集を先に実行し、検出結果に基づき最適なペイロードを提案：

```bash
fray test https://example.com --smart
```

```
  Stack:   wordpress (100%), nginx (70%)

  Recommended:
    1. sqli            (1200 payloads)
    2. xss             (800 payloads)
    3. path_traversal  (400 payloads)

  [Y] Run recommended  [A] Run all  [N] Cancel  [1,3] Pick:
```

[OWASPカバレッジ →](docs/owasp-complete-coverage.md)

---

## `fray detect` — 25社のWAF検出

```bash
fray detect https://example.com
```

Cloudflare、AWS WAF、Akamai、Imperva、F5 BIG-IP、Fastly、Azure WAF、Google Cloud Armor、Sucuri、Fortinet、Wallarm、Vercel 他13社

[検出シグネチャ →](docs/waf-detection-guide.md)

---

## 主要機能

| 機能 | 説明 | 例 |
|------|------|-----|
| **スコープ制限** | 許可されたドメイン/IP/CIDRのみに制限 | `--scope scope.txt` |
| **並行スキャン** | クロール + 注入を並列化（約3倍高速） | `-w 4` |
| **ステルスモード** | UA回転、ジッター、スロットル — 1フラグ | `--stealth` |
| **認証付きスキャン** | Cookie、Bearer、カスタムヘッダー | `--cookie "session=abc"` |
| **CI/CD** | GitHub Actions、PRコメント + バイパス時失敗 | `fray ci init` |

[認証ガイド →](docs/authentication-guide.md) · [スキャンオプション →](docs/scanning-guide.md) · [CIガイド →](docs/quickstart.md)

---

## 5,500以上のペイロード · 22カテゴリ · 120件のCVE

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS | 867 | SSRF | 167 |
| SQLi | 456 | SSTI | 98 |
| コマンドインジェクション | 234 | XXE | 123 |
| パストラバーサル | 189 | AI/LLMプロンプトインジェクション | 370 |

```bash
fray explain log4shell    # CVEインテリジェンス（ペイロード付き）
fray explain results.json # 検出結果の解説：影響度、修正方法、次のステップ
fray payloads             # 全カテゴリを一覧表示
```

[ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md)

---

## AI対応出力 — `--ai` フラグ

```bash
fray scan target.com --ai           # LLM最適化JSON出力
fray test target.com -c xss --ai    # AIワークフローにパイプ
fray recon target.com --ai           # Claude、GPT等向け構造化recon

# パイプライン例：
fray scan target.com --ai | ai analyze
```

出力：技術スタック、脆弱性（CWEタグ付き、信頼度スコア）、セキュリティ体制、推奨アクション — LLM直接消費用の構造化JSON。

## 攻撃サーフェスグラフ

```bash
fray graph example.com          # 攻撃サーフェス全体のビジュアルツリー
fray graph example.com --deep   # + JSエンドポイント + Wayback履歴URL
fray graph example.com --json   # 機械可読グラフ
```

出力：
```
🌐 example.com
├── 📂 Subdomains (8)
│   ├── 🔗 api.example.com
│   ├── 🔗 admin.example.com
│   └── 🔗 cdn.example.com
├── 🛡️ WAF: Cloudflare
├── 📂 Technologies
│   ├── ⚙️ nginx (95%)
│   └── ⚙️ wordpress (70%)
├── 📂 Admin Panels (2)
│   └── 📍 /admin/ [200] OPEN
├── 📍 GraphQL: /graphql (introspection OPEN)
├── 📂 Exposed Files (3)
│   ├── 📄 .env
│   └── 📄 .git/config
└── 📂 Recommended Attacks
    ├── ⚔️ xss
    └── ⚔️ sqli
```

21項目のreconチェックをツリー表示に集約 — サブドメイン（crt.sh）、DNS、WAF/CDN、技術スタック、管理パネル、APIエンドポイント、GraphQL、露出ファイル、CORS問題、パラメータ、推奨攻撃カテゴリ。

## SARIF出力 — GitHubセキュリティタブ

```bash
fray scan target.com --sarif -o results.sarif    # スキャンからSARIF 2.1.0出力
fray test target.com -c xss --sarif -o results.sarif  # テストからSARIF出力

# GitHubにアップロード：
gh code-scanning upload-sarif --sarif results.sarif
```

Frayの検出結果がGitHubの**Security**タブにCodeQL・Semgrepと並んで表示されます。CWEタグ、重要度、ペイロード詳細付き。

## Diff — ビジュアル回帰テスト

```bash
fray diff before.json after.json        # 色分けビジュアルdiff
fray diff before.json after.json --json # 機械可読diff
```

Git風ビジュアル出力：回帰は**赤**（`- BLOCKED → + BYPASS`）、改善は**緑**（`- BYPASS → + BLOCKED`）、カテゴリ別内訳テーブル付き。回帰時は終了コード1 — CI/CDゲートに最適。

## MCPサーバー — AI連携

```bash
pip install 'fray[mcp]'
```

### Claude Desktop — ワンライナー設定

`~/Library/Application Support/Claude/claude_desktop_config.json` に追加：

```json
{
  "mcpServers": {
    "fray": {
      "command": "python",
      "args": ["-m", "fray.mcp_server"]
    }
  }
}
```

Claude Desktopを再起動。質問：*「CloudflareをバイパスするXSSペイロードは？」* → Frayの10個のMCPツールが直接呼び出されます。

### 10個のMCPツール

| ツール | 機能 |
|--------|------|
| `list_payload_categories` | 全24攻撃カテゴリを一覧 |
| `get_payloads` | カテゴリ別ペイロード取得 |
| `search_payloads` | 5,500+ペイロードを全文検索 |
| `get_waf_signatures` | 25ベンダーのWAFフィンガープリント |
| `get_cve_details` | CVE検索（ペイロード・重要度付き） |
| `suggest_payloads_for_waf` | 特定WAF向けバイパスペイロード推薦 |
| `analyze_scan_results` | スキャン結果のリスク評価 |
| `generate_bypass_strategy` | ブロックされたペイロードの変異戦略 |
| `explain_vulnerability` | ペイロードの危険性を初心者向けに解説 |
| `create_custom_payload` | 自然言語からペイロード生成 |

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

---

## プロジェクト構成

```
fray/
├── fray/
│   ├── cli.py              # CLIエントリーポイント
│   ├── scanner.py           # 自動スキャン：クロール → 注入
│   ├── recon.py             # 14項目の情報収集
│   ├── detector.py          # WAF検出（25社対応）
│   ├── tester.py            # ペイロードテストエンジン
│   ├── reporter.py          # HTML + Markdownレポート
│   ├── mcp_server.py        # AI連携用MCPサーバー
│   └── payloads/            # 5,500以上のペイロード（22カテゴリ）
├── tests/                   # 624テスト
├── docs/                    # 30ガイド
├── mcp.json                 # MCPマニフェスト（ツール・入出力定義）
├── smithery.yaml            # Smithery.aiレジストリマニフェスト
└── pyproject.toml           # pip install fray
```

---

## ロードマップ

- [x] 自動スキャン：クロール → 発見 → 注入（`fray scan`）
- [x] 反射型ペイロード検出（注入確認）
- [x] スコープファイル制限 + 並行ワーカー
- [x] 14項目の情報収集、スマートモード、WAF検出
- [x] HTML/Markdownレポート、MCPサーバー
- [ ] HackerOne API連携（自動送信）
- [ ] Webベースのレポートダッシュボード
- [ ] MLベースのペイロード有効性スコアリング

---

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 全ドキュメント（30ガイド）](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**
