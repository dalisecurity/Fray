# Fray — WAFバイパス & セキュリティテストツールキット

### ⚔️ *オープンソースのWebアプリケーションファイアウォール向けペネトレーションテストツール — 情報収集、スキャン、バイパス、堅牢化*

Frayは高速・オープンソースの**Webアプリケーションセキュリティ**スキャナーおよび**WAFバイパス**ツールキットです。ペネトレーションテスター、バグバウンティハンター、DevSecOpsチーム向けに、6,300以上のペイロードデータベース、27項目の情報収集、AIアシストWAF回避、OWASP堅牢化監査を依存関係ゼロの `pip install` で提供します。

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

- **バグバウンティハンター** — 隠れたパラメータ・古いエンドポイント発見、Cloudflare/AWS WAF/Akamaiバイパス、レポート作成
- **ペンテスター** — フル情報収集 + 自動脆弱性スキャン、クライアント向けHTMLレポート
- **ブルーチーム** — WAFルール検証、設定変更後の回帰テスト
- **DevSecOps** — CI/CDパイプラインでDAST、WAFバイパス検出時にビルド失敗
- **セキュリティリサーチャー** — WAF回避技術の発見、ペイロード投稿
- **学生** — インタラクティブCTFチュートリアル、OWASP Top 10攻撃手法をハンズオンで学習

---

## クイックスタート

```bash
pip install fray                # PyPI（全プラットフォーム）
sudo apt install fray            # Kali Linux / Debian
brew install fray                # macOS
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

<p align="center">
  <img src="docs/demo.gif" alt="Frayデモ — WAF検出とXSSバイパス" width="720">
</p>

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

**recon → scan → ai-bypass**をエンドツーエンドで実行。各フェーズ間に推奨アクションを表示。

---

## `fray scan` — 自動攻撃対象面マッピング

```bash
fray scan https://example.com -c xss -m 3 -w 4
fray scan https://target.com --scope scope.txt --stealth   # バグバウンティ
fray scan https://target.com --json -o results.json        # CI/CD
```

クロール → 注入ポイント発見（フォーム、URLパラメータ、JS API）→ ペイロードテスト → 反射検出（`↩ REFLECTED`）。429レート制限時は自動バックオフ。

<p align="center">
  <img src="docs/screenshot-scan.png" alt="Fray scan — クロール、注入、XSS反射検出" width="720">
</p>

[全スキャンオプション + 使用例 →](docs/scanning-guide.md)

---

## `fray recon` — 27項目の自動チェック

```bash
fray recon https://example.com
fray recon https://example.com --js --history --params   # フルデプス
```

| チェック項目 | 検出内容 |
|------------|--------|
| **パラメータ発見** | クエリ文字列、フォーム入力、JS APIエンドポイント |
| **パラメータマイニング** | 136個の一般的なパラメータ名をブルートフォース |
| **JSエンドポイント抽出** | LinkFinder型：隠しAPI、クラウドバケット、漏洩シークレット |
| **過去URL発見** | Wayback Machine、sitemap.xml、robots.txt |
| **GraphQLイントロスペクション** | 10個の一般的なパス、スキーマ公開検出 |
| **API発見** | Swagger/OpenAPIスペック、バージョン付きAPIルート |
| **Hostヘッダーインジェクション** | パスワードリセット / キャッシュポイズニング |
| **管理画面発見** | 70パス: `/admin`、`/wp-admin`、`/phpmyadmin`、`/actuator` |
| **TLS / ヘッダー / Cookie** | 証明書、HSTS、CSP、HttpOnly、SameSite |
| **DNS / CORS / フィンガープリント** | CDN検出、CORS設定不備、技術スタック |
| **WAFモード + ギャップ分析** | シグネチャ vs 異常検知 vs ハイブリッド、既知バイパスマトリックス |

その他：28件の公開ファイルプローブ（`.env`、`.git`、phpinfo）· crt.sh経由のサブドメイン · レート制限フィンガープリント

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

Cloudflare、AWS WAF、Akamai、Imperva、F5 BIG-IP、Fastly、Azure WAF、Google Cloud Armor、Sucuri、Fortinet、Wallarm、Vercel 他13社。シグネチャ型、異常検知型、ハイブリッドWAFモードを識別 — 最適なバイパス戦略選択に必須。

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

最大級のオープンソースWAFペイロードデータベース — 実践的なペネトレーションテストとバグバウンティ向けに厳選。

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS（クロスサイトスクリプティング） | 851 | SSRF | 71 |
| SQLインジェクション | 141 | SSTI | 205 |
| コマンドインジェクション（RCE） | 118 | XXE | 151 |
| パストラバーサル（LFI/RFI） | 277 | AI/LLMプロンプトインジェクション | 370 |

```bash
fray explain log4shell    # CVEインテリジェンス（ペイロード付き）
fray explain results.json # 検出結果の解説：影響度、修正方法、次のステップ
fray payloads             # 全カテゴリを一覧表示
```

[ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md)

---

## その他のコマンド

```bash
fray graph example.com --deep       # 攻撃サーフェスのビジュアルツリー（27項目）
fray scan target.com --ai           # AIエージェント向けLLM最適化JSON出力
fray scan target.com --sarif -o r.sarif  # SARIF → GitHubセキュリティタブ
fray diff before.json after.json    # 回帰テスト（バイパス時に終了コード1）
```

<p align="center">
  <img src="docs/screenshot-graph.png" alt="Fray graph — 攻撃サーフェスのビジュアルツリー" width="720">
</p>

## MCPサーバー — AIエージェント連携

Frayは[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)経由で14ツールを提供 — Claude Desktop、Claude Code、ChatGPT、CursorなどMCP対応クライアントからAIセキュリティエージェントとして利用可能。

```bash
pip install 'fray[mcp]'
```

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

質問：*「CloudflareをバイパスするXSSペイロードは？」* → Frayの14個のMCPツールが直接呼び出されます。

<details>
<summary><b>14個のMCPツール</b></summary>

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

</details>

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

---

<details>
<summary><b>ロードマップ</b></summary>

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

</details>

---

## Frayと他ツールの比較

| | Fray | Nuclei | XSStrike | wafw00f | sqlmap |
|-|------|--------|----------|---------|--------|
| **WAFバイパスエンジン** | ✅ AI + 変異 | ❌ | 部分的 | ❌ | Tamperスクリプト |
| **WAF検出** | 25社 + モード | テンプレート経由 | 基本 | 150社以上 | 基本 |
| **情報収集** | 27項目 | 別ツール | クロールのみ | ❌ | ❌ |
| **ペイロードDB** | 6,300以上内蔵 | コミュニティテンプレ | XSSのみ | ❌ | SQLiのみ |
| **OWASP堅牢化** | ✅ A-Fグレード | ❌ | ❌ | ❌ | ❌ |
| **MCP / AIエージェント** | 14ツール | ❌ | ❌ | ❌ | ❌ |
| **依存関係ゼロ** | ✅ 標準ライブラリのみ | Goバイナリ | pip | pip | pip |

Frayはこれらのツールの代替ではありません — WAF検出（wafw00f）と攻撃（sqlmap/XSStrike）の間を埋める、**検出 → 情報収集 → バイパス → 堅牢化**の完全ワークフローを提供します。

---

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 全ドキュメント（30ガイド）](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**

---

## 関連プロジェクト

- [wafw00f](https://github.com/EnableSecurity/wafw00f) — WAFフィンガープリント・検出（150社以上対応）
- [WhatWaf](https://github.com/Ekultek/WhatWaf) — WAF検出・バイパスツール
- [XSStrike](https://github.com/s0md3v/XSStrike) — WAF回避機能付き高度なXSSスキャナー
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQLインジェクション検出・攻撃ツール
- [Nuclei](https://github.com/projectdiscovery/nuclei) — テンプレートベースの脆弱性スキャナー
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Webセキュリティペイロード・バイパス集
- [SecLists](https://github.com/danielmiessler/SecLists) — セキュリティ評価用ワードリスト
- [Awesome WAF](https://github.com/0xInfection/Awesome-WAF) — WAFツール・バイパスのキュレーションリスト
