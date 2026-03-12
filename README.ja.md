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

---

## 🆕 最新アップデート

### インタラクティブ・ポストリコンメニュー

`fray recon` 完了後、検出結果に基づいたスマートな対話メニューを自動表示します。

```
  ┌────────────────────────────────────────────────────────────┐
  │  🎯 リコン完了 — 次のステップは？                          │
  ├────────────────────────────────────────────────────────────┤
  │  検出: 🔴 2 critical, 🟠 2 high, 🟡 1 medium              │
  │  WAF: Cloudflare                                          │
  │  リスク: 85/100 (CRITICAL)                                │
  ├────────────────────────────────────────────────────────────┤
  │  [1] 📄 HTMLレポート生成                                   │
  │  [2] 🔴 XSSテスト — 検索パラメータqに反射型XSS             │
  │  [3] 🔴 SQLiテスト — /api/users?id=1でエラーベース         │
  │  [4] 🟠 キャッシュポイズニング — X-Forwarded-Hostヘッダ    │
  │  [5] 🔬 ディープスキャン — 全脆弱性テスト                  │
  │  [6] 🚀 オートパイロット（レポート＋全テスト）             │
  │  [q] 終了                                                 │
  └────────────────────────────────────────────────────────────┘
```

オプションは**実際の検出結果から動的に生成**されます。ランダムなペイロードではなく、リコンでXSSが見つかればXSSをテストし、SQLエラーが見つかればSQLiをテストします。`--no-interactive` で無効化可能。

### CVE固有ペイロード

| CVE | 製品 | 手法 | モジュール |
|-----|------|------|-----------|
| **CVE-2026-1281** | Ivanti Endpoint Manager Mobile | Apache RewriteMap経由のシェル算術展開 `$((7*7))` | `fray/cmdi.py` |
| **CVE-2026-1340** | Ivanti Endpoint Manager Mobile | `/mi/bin/map-appstore-url` のBashスクリプト未サニタイズ | `fray/cmdi.py` |
| **CSPヘッダXSS** | Cloudflare緊急WAFルール 2026-03-12 | `Content-Security-Policy` ヘッダインジェクション | `fray/xss.py` |

### 🤖 LLM / AIエンドポイント検出

リコンパイプラインが公開されたAI/LLMインフラを自動検出 — 2025-2026年最大の攻撃対象領域：

- **50以上のAI APIパス** — Ollama、LocalAI、LiteLLM、OpenWebUI、vLLM、Hugging Face TGI、NVIDIA Triton
- **14のレスポンスフィンガープリント** — LLMストリーミング応答、モデルメタデータ、トークン使用量を検出
- **17のポートプローブ** — 一般的なAIサービスポート（11434、8080、3000、7860、8501等）
- **21のAIプロキシヘッダ** — `X-AI-Model`、`X-LLM-Provider`、`X-OpenAI-*`、Anthropic/Cohere/Replicate
- **プロンプトインジェクション** — `ai_llm_injection` カテゴリに370のペイロード内蔵

```bash
fray recon https://target.com     # Tier 3でLLM/AIエンドポイントを自動検出
fray test https://target.com -c ai_llm_injection --smart   # プロンプトインジェクションテスト
```

### 🔐 VPNゲートウェイ検出

リコンが公開されたVPNログインポータルを特定 — エンタープライズ侵入チェーンの一般的な標的：

| ベンダー | 検出パス |
|---------|---------|
| **Fortinet FortiGate** | `/remote/login`、`/remote/fgt_lang` |
| **Palo Alto GlobalProtect** | `/ssl-vpn/login.esp`、`/global-protect/login.esp` |
| **Cisco AnyConnect** | `/+CSCOE+/logon.html` |
| **Citrix NetScaler** | `/vpn/index.html`、`/logon/LogonPoint/` |
| **Check Point** | `/sslvpn/Login/Login` |
| **Juniper/Pulse** | `/dana-na/auth/url_default/welcome.cgi` |
| **OpenVPN** | `/__session_start__/` |

### ディープスキャンモジュール

6つの新しい深層脆弱性テストモジュール — ランダムペイロードではなく、手法駆動型スキャナ：

| モジュール | 手法 | 特徴 |
|-----------|------|------|
| **`CMDiScanner`** | 結果ベース、タイムブラインド、ファイルベース、エラーベース、ネスト、**Ivanti CVE** | OS検出、9セパレータ、偽陽性防止 |
| **`XSSScanner`** | コンテキスト認識、DOM解析、WAF回避、**CSPヘッダインジェクション** | 6反射コンテキスト、フィルタ検出 |
| **`SQLiInjector`** | エラーベース、UNION、ブールブラインド、タイムブラインド | カラム列挙、DBMSフィンガープリント |
| **`CachePoisonScanner`** | 15のアンキーヘッダ、パス混乱、デセプション | CDN検出、キャッシュキー分析 |
| **`MassAssignScanner`** | 隠しパラメータ、HPP、型ジャグリング | 権限昇格、アカウント状態 |
| **`DeserScanner`** | 技術検出、ガジェットチェーン探索 | Java、PHP、Python、.NET、Ruby |

### 統一v11ダークテーマレポート

全HTMLレポートが同一ダークテーマを使用 — リコンレポート、スキャンレポート、WAFテストレポート間でフォント（Inter）、配色、レイアウトが統一されました。

---

## Frayと他ツールの比較

| | Fray | Nuclei | XSStrike | wafw00f | sqlmap |
|-|------|--------|----------|---------|--------|
| **WAFバイパスエンジン** | ✅ AI + 変異 | ❌ | 部分的 | ❌ | Tamperスクリプト |
| **WAF検出** | 25社 + モード | テンプレート経由 | 基本 | 150社以上 | 基本 |
| **情報収集** | 27項目 | 別ツール | クロールのみ | ❌ | ❌ |
| **ペイロードDB** | 4,000以上内蔵 | コミュニティテンプレ | XSSのみ | ❌ | SQLiのみ |
| **OWASP堅牢化** | ✅ A-Fグレード | ❌ | ❌ | ❌ | ❌ |
| **MCP / AIエージェント** | 14ツール | ❌ | ❌ | ❌ | ❌ |
| **依存関係ゼロ** | ✅ 標準ライブラリのみ | Goバイナリ | pip | pip | pip |

多くのペイロード集は静的なテキストファイルに過ぎません。Frayは完全な**検出 → 情報収集 → スキャン → バイパス → 堅牢化**ワークフローを1つの `pip install` で提供します。

---

## クイックスタート

```bash
pip install fray                # PyPI（全プラットフォーム）
sudo apt install fray            # Kali Linux / Debian
brew install fray                # macOS
```

```bash
fray auto https://example.com          # フルパイプライン：recon → scan → bypass
fray scan https://example.com          # 自動クロール → 注入 → 反射検出
fray recon https://example.com         # 27項目の情報収集
```

<p align="center">
  <img src="docs/demo.gif" alt="Frayデモ — WAF検出とXSSバイパス" width="720">
</p>

Frayがリコンワークフローに役立ったら、ぜひ[⭐ スター](https://github.com/dalisecurity/fray)をお願いします — 他の人が見つけやすくなります。

---

## Frayの機能

| コマンド | 説明 |
|---------|------|
| **`fray auto`** | フルパイプライン：recon → scan → ai-bypass を一括実行 |
| **`fray scan`** | クロール → パラメータ発見 → ペイロード注入 → 反射検出 |
| **`fray recon`** | 27項目：TLS、DNS、サブドメイン、CORS、パラメータ、JS、API、管理画面、WAFインテル |
| **`fray ai-bypass`** | WAFプローブ → LLMペイロード生成 → テスト → 変異 → ヘッダー操作 |
| **`fray bypass`** | 5フェーズWAF回避スコアラー：変異フィードバックループ |
| **`fray harden`** | セキュリティヘッダー（A-Fグレード） + OWASP Top 10設定不備チェック + 修正スニペット |
| **`fray detect`** | 25社のWAFベンダーをフィンガープリント（シグネチャ / 異常検知 / ハイブリッド） |
| **`fray test`** | 4,000以上のペイロードを23カテゴリで適応型スロットル付きテスト |
| **`fray graph`** | 攻撃サーフェスのビジュアルツリー |

<p align="center">
  <img src="docs/screenshot-scan.png" alt="Fray scan — クロール、注入、XSS反射検出" width="720">
</p>

**組み込みオプション：** `--scope`（スコープ制限）· `--stealth`（UA回転、ジッター）· `-w 4`（並行）· `--cookie` / `--bearer`（認証）· `--sarif`（GitHubセキュリティタブ）· `--json` · `--ai`（LLM出力）

[スキャンガイド →](docs/scanning-guide.md) · [情報収集ガイド →](docs/quickstart.md) · [認証ガイド →](docs/authentication-guide.md) · [CI/CDガイド →](docs/quickstart.md)

---

## VS Code拡張機能

エディタから直接Frayを実行 — スキャン、テスト、バイパス、検出、堅牢化をVS Codeから離れずに実行可能。

[![Marketplaceからインストール](https://img.shields.io/badge/Install-VS%20Code%20Marketplace-007ACC?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)

```
Cmd+Shift+P → "Fray: Run Command..."
```

- **11コマンド** — Scan、Test、Bypass、Detect、Harden、Recon、OSINT、Leak Searchなど
- **右クリックスキャン** — ファイル内のURLを選択 → コンテキストメニュー → スキャン
- **HTMLレポート** — エディタ内にリッチなレポート表示（`Cmd+Shift+R`）
- **インライン診断** — バイパス結果がエディタ内に警告/エラーとして表示
- **アクティビティバー** — 結果とスキャン履歴をサイドバーで参照
- **ステータスバー** — スキャン進捗をリアルタイム表示

[拡張機能README →](vscode-fray/README.md)

---

## MCPサーバー — AIエージェント連携

Frayは[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)経由で**14ツール**を提供 — Claude Desktop、Claude Code、ChatGPT、CursorなどMCP対応クライアントからAIセキュリティエージェントとして利用可能。

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

[Claude Codeガイド →](docs/claude-code-guide.md) · [ChatGPTガイド →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

| ツール | 機能 |
|--------|------|
| `suggest_payloads_for_waf` | 特定WAF向けバイパスペイロード推薦 |
| `generate_bypass_strategy` | ブロックされたペイロードの変異戦略 |
| `search_payloads` | 4,000+ペイロードを全文検索 |
| `analyze_response` | 偽陰性検出：ソフトブロック、チャレンジ |
| `hardening_check` | セキュリティヘッダー監査（グレード + レート制限チェック） |

[全14個のMCPツールを見る →](docs/claude-code-guide.md)

---

## 4,000以上のペイロード · 23カテゴリ · 175件のCVE

最大級のオープンソースWAFペイロードデータベース — 実践的なペネトレーションテストとバグバウンティ向けに厳選。

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS（クロスサイトスクリプティング） | 1,209 | SSRF | 122 |
| SQLインジェクション | 248 | SSTI | 122 |
| コマンドインジェクション（RCE） | 200 | XXE | 84 |
| AI/LLMプロンプトインジェクション | 370 | パストラバーサル（LFI/RFI） | 109 |
| モダンバイパス | 137 | CSPバイパス | 104 |
| APIセキュリティ | 130 | プロトタイプ汚染 | 110 |

[ペイロードデータベース →](docs/payload-database-coverage.md) · [CVEカバレッジ →](docs/cve-real-world-bypasses.md)

---

## 高度な使い方

```bash
fray graph example.com --deep       # 攻撃サーフェスのビジュアルツリー（27項目）
fray ai-bypass target.com -c xss    # AI適応型バイパス（LLM/ローカル）
fray harden target.com              # OWASP堅牢化監査（A-Fグレード + 修正スニペット）
fray explain log4shell              # CVEインテリジェンス（ペイロード付き）
fray diff before.json after.json    # 回帰テスト（バイパス時に終了コード1）
fray report results.json --html     # クライアント向けHTMLレポート
```

<p align="center">
  <img src="docs/screenshot-graph.png" alt="Fray graph — 攻撃サーフェスのビジュアルツリー" width="720">
</p>

[WAF検出ガイド →](docs/waf-detection-guide.md) · [全ドキュメント（30ガイド） →](docs/)

---

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。AIコーディングエージェントは [AGENTS.md](AGENTS.md) を参照。

ご質問は [Discussions](https://github.com/dalisecurity/fray/discussions) または [ドキュメント](docs/) をご覧ください。

## 法的事項

**MITライセンス** — [LICENSE](LICENSE) を参照。所有または明示的な許可を得たシステムのみテストしてください。

**セキュリティ問題：** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 ドキュメント](docs/) · [ロードマップ](docs/roadmap.md) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**

## 関連プロジェクト

- [wafw00f](https://github.com/EnableSecurity/wafw00f) — WAFフィンガープリント・検出（150社以上対応）
- [WhatWaf](https://github.com/Ekultek/WhatWaf) — WAF検出・バイパスツール
- [XSStrike](https://github.com/s0md3v/XSStrike) — WAF回避機能付き高度なXSSスキャナー
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQLインジェクション検出・攻撃ツール
- [Nuclei](https://github.com/projectdiscovery/nuclei) — テンプレートベースの脆弱性スキャナー
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Webセキュリティペイロード・バイパス集
- [SecLists](https://github.com/danielmiessler/SecLists) — セキュリティ評価用ワードリスト
- [Awesome WAF](https://github.com/0xInfection/Awesome-WAF) — WAFツール・バイパスのキュレーションリスト
