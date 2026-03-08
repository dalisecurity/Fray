# Fray — WAFバイパス & セキュリティテストツールキット

**🌐 Language:** [English](README.md) | **日本語**

### ⚔️ *オープンソースWAFバイパスツールキット — 情報収集、スキャン、バイパス、堅牢化。依存関係ゼロ。*

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> **正規の許可を得たセキュリティテスト専用** — 自身が所有する、または書面で明示的に許可を得たシステムのみテストしてください。

Frayは[wafw00f](https://github.com/EnableSecurity/wafw00f)（検出）と[sqlmap](https://github.com/sqlmapproject/sqlmap)（攻撃）の間を埋めるツール — 完全な**情報収集 → バイパス → 堅牢化**パイプラインを1つの `pip install` で提供します。

---

## Frayと他ツールの比較

| | Fray | Nuclei | XSStrike | wafw00f | sqlmap |
|-|------|--------|----------|---------|--------|
| **WAFバイパスエンジン** | ✅ AI + 変異 | ❌ | 部分的 | ❌ | Tamperスクリプト |
| **WAF検出** | 25社 + モード | テンプレート経由 | 基本 | 150社以上 | 基本 |
| **情報収集** | 27項目 | 別ツール | クロールのみ | ❌ | ❌ |
| **ペイロードDB** | 2,900以上内蔵 | コミュニティテンプレ | XSSのみ | ❌ | SQLiのみ |
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
| **`fray test`** | 2,900以上のペイロードを23カテゴリで適応型スロットル付きテスト |
| **`fray graph`** | 攻撃サーフェスのビジュアルツリー |

<p align="center">
  <img src="docs/screenshot-scan.png" alt="Fray scan — クロール、注入、XSS反射検出" width="720">
</p>

**組み込みオプション：** `--scope`（スコープ制限）· `--stealth`（UA回転、ジッター）· `-w 4`（並行）· `--cookie` / `--bearer`（認証）· `--sarif`（GitHubセキュリティタブ）· `--json` · `--ai`（LLM出力）

[スキャンガイド →](docs/scanning-guide.md) · [情報収集ガイド →](docs/quickstart.md) · [認証ガイド →](docs/authentication-guide.md) · [CI/CDガイド →](docs/quickstart.md)

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
| `search_payloads` | 2,900+ペイロードを全文検索 |
| `analyze_response` | 偽陰性検出：ソフトブロック、チャレンジ |
| `hardening_check` | セキュリティヘッダー監査（グレード + レート制限チェック） |

[全14個のMCPツールを見る →](docs/claude-code-guide.md)

---

## 2,900以上のペイロード · 23カテゴリ · 175件のCVE

最大級のオープンソースWAFペイロードデータベース — 実践的なペネトレーションテストとバグバウンティ向けに厳選。

| カテゴリ | 件数 | カテゴリ | 件数 |
|---------|-----|---------|-----|
| XSS（クロスサイトスクリプティング） | 989 | SSRF | 72 |
| SQLインジェクション | 148 | SSTI | 62 |
| コマンドインジェクション（RCE） | 125 | XXE | 34 |
| AI/LLMプロンプトインジェクション | 370 | パストラバーサル（LFI/RFI） | 59 |
| モダンバイパス | 137 | CSPバイパス | 64 |
| APIセキュリティ | 80 | プロトタイプ汚染 | 75 |

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
