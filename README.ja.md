# Fray

### ⚔️ *オープンソースWAFセキュリティテストツールキット — 情報収集、スキャン、バイパス、堅牢化*

[![Payloads](https://img.shields.io/badge/ペイロード-6300+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF検出-25社+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/情報収集チェック-27項目-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
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

- **`fray auto`** — フルパイプライン：recon → scan → ai-bypass を一括実行 *(新機能)*
- **`fray scan`** — 自動クロール → パラメータ発見 → ペイロード注入
- **`fray recon`** — 27項目の自動チェック（TLS、ヘッダー、DNS、CORS、パラメータ、JS、過去URL、GraphQL、API、Host注入、管理画面）
- **`fray ai-bypass`** — LLMアシスト適応型バイパス：レスポンス差分分析 + ヘッダー操作 *(新機能)*
- **`fray bypass`** — 5フェーズWAF回避スコアラー：変異フィードバックループ
- **`fray harden`** — OWASP Top 10設定不備チェック + セキュリティヘッダー監査 + 修正スニペット *(新機能)*
- **`fray detect`** — 25社のWAFベンダーをフィンガープリント
- **`fray test`** — 6,300以上のペイロード（24のOWASPカテゴリ）
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
fray auto https://example.com                    # フルパイプライン：recon → scan → bypass
fray scan https://example.com                    # 自動スキャン（クロール + 注入）
fray recon https://example.com                   # 27項目の情報収集
fray ai-bypass https://example.com               # AI適応型バイパス
fray bypass https://example.com -c xss           # WAF回避スコアラー
fray harden https://example.com                  # OWASP堅牢化監査
fray test https://example.com --smart            # スマートペイロードテスト
fray detect https://example.com                  # WAF検出
fray explain CVE-2021-44228                      # CVEインテリジェンス
```

---

## コマンド一覧

| コマンド | 説明 |
|---------|------|
| **`fray auto`** | フルパイプライン：recon → scan → ai-bypass（フェーズ間に推奨アクション表示） |
| **`fray scan`** | クロール → パラメータ発見 → ペイロード注入 → 反射検出 |
| **`fray recon`** | 27項目：TLS、ヘッダー、DNS、サブドメイン、CORS、パラメータ、JS、API、管理画面、WAFインテル |
| **`fray ai-bypass`** | 適応型バイパス：WAFプローブ → ペイロード生成（LLM/ローカル） → テスト → 変異 → ヘッダー操作 |
| **`fray bypass`** | 5フェーズWAF回避：プローブ → ランク → テスト → ブロック変異 → ブルートフォース |
| **`fray harden`** | セキュリティヘッダー監査（A-Fグレード） + OWASP Top 10設定不備チェック + 修正スニペット |
| **`fray test`** | 6,300以上のペイロードを24カテゴリで適応型スロットル付きテスト |
| **`fray detect`** | 25社のWAFベンダーをフィンガープリント |
| **`fray report`** | スキャン結果からHTML/Markdownレポート生成 |
| **`fray explain`** | CVEインテリジェンス（ペイロード付き）、検出結果の解説 |
| **`fray diff`** | Before/After回帰テスト（CI/CDゲート） |
| **`fray graph`** | 攻撃サーフェスのビジュアルツリー |

---

## `fray auto` — フルパイプライン

```bash
fray auto https://example.com -c xss
fray auto https://example.com --skip-recon       # reconスキップ、scan + bypassのみ
fray auto https://example.com --json -o report.json
```

```
───── Phase 1: Reconnaissance ─────
  Risk: HIGH (56/100)  WAF: Cloudflare  Subdomains: 186
  → Recommended: fray test target -c csp_bypass

───── Phase 2: WAF Scan ─────
  [1/20] BLOCKED  403 │ Async/await exfiltration
  [2/20] BLOCKED  403 │ Promise-based XSS
  → 100% blocked: AI bypass will try adaptive mutations

───── Phase 3: AI Bypass ─────
  BLOCKED  403 │ local:url_encode
  SKIP     400 │ Transfer-Encoding: chunked (not a real bypass)

───── Pipeline Complete ─────
╭── Pipeline Summary ──╮
│ Recon Risk   HIGH    │
│ WAF          CF      │
│ Scan         0/20    │
│ AI Bypass    0/8     │
│ Header       0       │
╰──────────────────────╯
  Next steps:
    fray test target -c csp_bypass --max 50
    fray bypass target -c xss --mutation-budget 50
    fray harden target
```

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

## `fray recon` — 27項目の自動チェック

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
| **レート制限フィンガープリント** | 閾値マッピング（429前のreq/s）、バースト制限、ロックアウト時間、安全な遅延 |
| **WAF検出モード** | シグネチャ vs 異常検知 vs ハイブリッド — ボディ差分、タイミング差分、ヘッダー差分 |
| **WAFルールギャップ分析** | ベンダー別の既知バイパス手法、検出ギャップ、テクニックマトリックスとの自動照合 |

その他：28件の公開ファイルプローブ（`.env`、`.git`、phpinfo、actuator）· crt.sh経由のサブドメイン列挙

`--js` はインラインおよび外部JavaScriptファイルをLinkFinder型で解析 — `fetch()`、`axios`、`XMLHttpRequest` 呼び出し、完全URL、内部ホスト名/サブドメイン、クラウドストレージバケット（AWS S3、GCS、Azure Blob、Firebase、DO Spaces）、漏洩シークレット（AWSキー、Google APIキー、GitHubトークン、Stripeキー、Slack Webhook、JWT、Bearerトークン、汎用APIキー）。

`--history` はWayback Machine CDX API、sitemap.xml、robots.txt Disallowパスを検索。古いエンドポイントはWAFルールが弱いことが多いです。

`--params` は136個の一般的なパラメータ名をブルートフォース。レスポンス差分（ステータス、サイズ、反射）で隠れたパラメータを検出。リスク評価：HIGH（SSRF/LFI/インジェクション）、MEDIUM（XSS/IDOR）。

GraphQLイントロスペクションはフルrecon時に自動実行。`/graphql`、`/api/graphql`、`/v1/graphql`、`/graphiql`、`/playground`等をプローブします。

API発見は30以上の一般的なパスをプローブ：`swagger.json`、`openapi.json`、`/api-docs`、`/swagger-ui/`、バージョン付きAPIルート。スペックを解析して全エンドポイント、メソッド、認証方式を抽出します。

**Fray初めて？** `fray help` で全コマンドのガイドを表示。

[情報収集ガイド →](docs/quickstart.md)

---

## `fray ai-bypass` — AI適応型バイパス

```bash
fray ai-bypass https://example.com -c xss --rounds 3
OPENAI_API_KEY=sk-... fray ai-bypass https://example.com   # LLMモード
```

| フェーズ | 処理内容 |
|---------|----------|
| **プローブ** | WAF挙動を学習：ブロックタグ、イベント、キーワード、厳格度 |
| **生成** | LLMまたはローカルエンジンが標的ペイロードを作成 |
| **テスト + 差分** | レスポンス差分分析：ソフトブロック、チャレンジ、反射 |
| **適応** | 結果をフィードバック → よりスマートなペイロードを再生成 |
| **ヘッダー** | X-Forwarded-For、Transfer-Encoding、Content-Type混乱 |

**プロバイダー：** OpenAI（`OPENAI_API_KEY`）、Anthropic（`ANTHROPIC_API_KEY`）、ローカル（キー不要）。

## `fray harden` — OWASP堅牢化監査

```bash
fray harden https://example.com
fray harden https://example.com --json -o audit.json
```

セキュリティヘッダー（HSTS、CSP、COOP、CORP、Permissions-Policy、レート制限ヘッダー）を**A-Fグレード**で評価。OWASP Top 10設定不備チェック（A01アクセス制御、A02暗号、A05設定不備、A06コンポーネント、A07認証）。**nginx、Apache、Cloudflare Workers、Next.js**向けコピペ修正スニペットを出力。

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

## 6,300以上のペイロード · 24カテゴリ · 162件のCVE

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS | 851 | SSRF | 71 |
| SQLi | 141 | SSTI | 205 |
| コマンドインジェクション | 118 | XXE | 151 |
| パストラバーサル | 277 | AI/LLMプロンプトインジェクション | 370 |

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

27項目のreconチェックをツリー表示に集約 — サブドメイン（crt.sh）、DNS、WAF/CDN、技術スタック、管理パネル、APIエンドポイント、GraphQL、露出ファイル、CORS問題、パラメータ、推奨攻撃カテゴリ。

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

Claude Desktopを再起動。質問：*「CloudflareをバイパスするXSSペイロードは？」* → Frayの14個のMCPツールが直接呼び出されます。

### 14個のMCPツール

| ツール | 機能 |
|--------|------|
| `list_payload_categories` | 全24攻撃カテゴリを一覧 |
| `get_payloads` | カテゴリ別ペイロード取得 |
| `search_payloads` | 6,300+ペイロードを全文検索 |
| `get_waf_signatures` | 25ベンダーのWAFフィンガープリント |
| `get_cve_details` | CVE検索（ペイロード・重要度付き） |
| `suggest_payloads_for_waf` | 特定WAF向けバイパスペイロード推薦 |
| `analyze_scan_results` | スキャン結果のリスク評価 |
| `generate_bypass_strategy` | ブロックされたペイロードの変異戦略 |
| `explain_vulnerability` | ペイロードの危険性を初心者向けに解説 |
| `create_custom_payload` | 自然言語からペイロード生成 |
| `ai_suggest_payloads` | WAFインテルを活用したコンテキスト対応ペイロード生成 |
| `analyze_response` | 偽陰性検出：ソフトブロック、チャレンジ、反射分析 |
| `hardening_check` | セキュリティヘッダー監査（グレード + レート制限チェック） |
| `owasp_misconfig_check` | OWASP A01/A02/A03/A05/A06/A07チェック |

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

---

## プロジェクト構成

```
fray/
├── fray/
│   ├── cli.py              # CLIエントリーポイント（auto, scan, recon, bypass, harden, ...）
│   ├── scanner.py           # 自動スキャン：クロール → 注入
│   ├── ai_bypass.py         # AI適応型バイパスエンジン
│   ├── bypass.py            # 5フェーズWAF回避スコアラー
│   ├── mutator.py           # 20戦略ペイロード変異エンジン
│   ├── recon/               # 27項目の情報収集パイプライン
│   ├── detector.py          # WAF検出（25社対応）
│   ├── tester.py            # ペイロードテスト + 適応型スロットル
│   ├── reporter.py          # HTML + Markdownレポート
│   ├── mcp_server.py        # MCPサーバー（14ツール）
│   └── payloads/            # 6,300以上のペイロード（24カテゴリ）
├── tests/                   # 846テスト
├── docs/                    # 30ガイド
├── mcp.json                 # MCPマニフェスト
└── pyproject.toml           # pip install fray
```

---

## ロードマップ

- [x] フルパイプライン：`fray auto`（recon → scan → ai-bypass）
- [x] AI適応型バイパス + LLM連携（OpenAI/Anthropic）
- [x] 5フェーズWAF回避スコアラー + 変異フィードバックループ
- [x] OWASP堅牢化チェック + セキュリティヘッダー監査
- [x] 20戦略ペイロード変異エンジン
- [x] 自動スキャン：クロール → 発見 → 注入（`fray scan`）
- [x] 27項目の情報収集、スマートモード、WAF検出
- [x] 14 MCPツール、HTML/Markdownレポート、SARIF出力
- [ ] HackerOne API連携（自動送信）
- [ ] Webベースのレポートダッシュボード

---

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 全ドキュメント（30ガイド）](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**
