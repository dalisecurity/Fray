# Fray

### ⚔️ *オープンソースWAFセキュリティテストツールキット — スキャン、検出、テスト、レポート*

[![Payloads](https://img.shields.io/badge/ペイロード-5500+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF検出-25社+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/情報収集チェック-17項目-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
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
- **`fray recon`** — 17項目の自動チェック（TLS、ヘッダー、DNS、パラメータ発見、JS抽出、過去URL）
- **`fray detect`** — 25社のWAFベンダーをフィンガープリント
- **`fray test`** — 5,500以上のペイロード（22のOWASPカテゴリ）
- **`fray report`** — HTML・Markdownレポート
- **依存関係ゼロ** — Python標準ライブラリのみ。`pip install fray` ですぐ使える

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

## `fray recon` — 17項目の自動チェック

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
| **JSエンドポイント抽出** | 隠しAPI、管理画面ルート、GraphQL、認証エンドポイントを`.js`ファイルから発見 |
| **過去URL発見** | Wayback Machine、sitemap.xml、robots.txtから古いエンドポイントを取得 |
| **TLS** | バージョン、暗号スイート、証明書有効期限 |
| **セキュリティヘッダー** | HSTS、CSP、X-Frame-Options（スコア付き） |
| **Cookie** | HttpOnly、Secure、SameSiteフラグ |
| **フィンガープリント** | WordPress、PHP、Node.js、nginx、Apache、Java、.NET |
| **DNS** | A/CNAME/MX/TXT、CDN検出、SPF/DMARC |
| **CORS** | ワイルドカード、反射型オリジン、認証情報の設定不備 |

その他：28件の公開ファイルプローブ（`.env`、`.git`、phpinfo、actuator）· crt.sh経由のサブドメイン列挙

`--js` はインラインおよび外部JavaScriptファイルから `fetch()`、`axios`、`XMLHttpRequest`、`/api/`、`/graphql`、`/admin/`、`/internal/` パスを解析します。

`--history` はWayback Machine CDX API、sitemap.xml、robots.txt Disallowパスを検索。古いエンドポイントはWAFルールが弱いことが多いです。

`--params` は136個の一般的なパラメータ名をブルートフォース。レスポンス差分（ステータス、サイズ、反射）で隠れたパラメータを検出。リスク評価：HIGH（SSRF/LFI/インジェクション）、MEDIUM（XSS/IDOR）。

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
fray payloads             # 全カテゴリを一覧表示
```

[ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md)

---

## MCPサーバー — AI連携

```bash
pip install fray[mcp]
fray mcp
```

Claudeに質問：*「CloudflareをバイパスするXSSペイロードは？」* → FrayのMCPツールが直接呼び出されます。

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md)

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
