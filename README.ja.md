# agent-zerotrust

[English](README.md) | **日本語**

**AIエージェントのためのゼロトラスト・セキュリティゲートウェイ**

AIエージェントにマシンへの本物のアクセスを与える。ただし、信用はしない。

`agent-zerotrust` は、AIエージェント（Muse など）にローカル環境への
監査可能で制約されたアクセスを提供し、事後に「実際に何をしたのか」を
証明できるようにする、オープンな共通基盤です。SSHに加えて、ローカルのCLI
エージェント（Codex、DSH、OpenCode、Command Code、Mistral Vibe、
Antigravity）に作業を委譲することもでき、リモートのエージェントに
それらの認証情報を渡すことはありません。

> ステータス: デプロイ済み・稼働中。Phase 1（監査可能なSSHアクセス）と
> Phase 2（自動レビュー、Telegram通知、MCP承認、LLMバックエンド）は完了、
> Phase 3（特権ブローカー＋署名済みリース）はコア完了です。
> 稼働記録は [deploy/README.md](deploy/README.md)、残項目は
> [ロードマップ](docs/roadmap.md) を参照してください。

## なぜ必要か

AIエージェントは、開発マシンへの事実上のインタラクティブシェルアクセスを
手にしつつあります。主流のモデルは*エージェントを信用する*ことです。
SSH鍵を渡して、その行動がスコープ内に収まることを祈るだけ。

Meta の
[Muse のセキュリティアプローチ](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)
はエージェント自身の実行環境を守ります。独立した Sentinel が権限制御を
担当し、ランタイムはサンドボックス化され、eBPFが通信を制限する。
それはエージェント側を守る仕組みです。

このプロジェクトは、その反対側を守ります。エージェントが接続してくる
マシンです。あなたのデータ、あなたの認証情報、その背後にあるLANごと。

前提はゼロトラストです。

- 認証されたセッションは、信用されたセッションではない
- すべての操作は仲介され、記録され、説明可能である
- 証拠は、監視対象が決して届けない場所に置かれる
- セキュリティの基盤はAIなしで機能する。Guardian AI はその上に意味分析を
  追加するオプションの層であり、それが落ちても基盤は動き続ける

## アーキテクチャ

```mermaid
flowchart TB
    subgraph agents["AIエージェント"]
        muse["Muse<br/><i>リモート · SSH + MCP</i>"]
        local["Claude Code / Codex<br/><i>将来: ローカルエージェント</i>"]
    end

    subgraph tailnet["Tailscale · 経路制限"]
        acl["ACL: エージェント → :22, :8930 のみ"]
    end

    subgraph bastion["Warpgate · SSH要塞"]
        wg["エージェントごとの認証<br/>セッション録画・再生"]
    end

    subgraph protected["保護ホスト · Linux"]
        user["<code>ai-muse</code><br/>非特権 · sudoなし"]
        tg["<b>Tetragon (eBPF)</b><br/>カーネルレベルの事実<br/>実行 · ファイル · 通信"]
        broker["<b>特権ブローカー</b><br/>唯一の特権ドア<br/>署名済みリースを検証"]
    end

    subgraph gateway["ゲートウェイサービス"]
        mcp["<b>MCP Gateway (:8930)</b><br/>承認 + ワーカー委譲"]
        watcher["セッションウォッチャー<br/>自動レビュー + 通知"]
        workers["<b>Worker Gateway</b><br/>codex · dsh · opencode<br/>commandcode · vibe · agy"]
    end

    subgraph windows["Windowsホスト (GPU)"]
        win["RTX 4090 · <code>conta</code>環境<br/><i>ssh windows 経由</i>"]
    end

    subgraph monitoring["監視ホスト"]
        store[("証拠ストア<br/>録画 + イベント")]
        guardian["Guardian AI <i>(オプション)</i><br/>証拠 vs 申告<br/>リスク評価"]
        ids["IDS · 通知"]
    end

    human(["人間（オーナー）<br/>Telegram · 管理UI"])

    muse -->|"ssh"| acl
    local -.->|"将来"| acl
    acl -->|"22番のみ"| wg
    acl -->|"8930番のみ"| mcp
    wg -->|"ai-muse として"| user
    user -->|"全システムコール"| tg
    user -->|"azt-broker"| broker
    user -->|"azt-worker / MCP"| mcp
    mcp -->|"dispatch_task"| workers
    workers -->|"ssh windows"| win
    tg -->|"一方向の証拠"| store
    broker -->|"リース償還"| store
    store --> guardian
    guardian --> ids
    watcher --> guardian
    watcher -->|"ブリーフィング"| human
    mcp -->|"承認リクエスト"| human
    human -->|"✅ / 🚫"| mcp
    mcp -->|"署名済みリース"| broker

    classDef agent fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    classDef bastionBox fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef hostBox fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    classDef controlBox fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef monBox fill:#eceff1,stroke:#546e7a,stroke-width:2px
    classDef humanBox fill:#fffde7,stroke:#fbc02d,stroke-width:2px
    classDef winBox fill:#e0f7fa,stroke:#00838f,stroke-width:2px

    class muse,local agent
    class acl,wg bastionBox
    class user,tg,broker hostBox
    class mcp,watcher,workers controlBox
    class store,guardian,ids monBox
    class human humanBox
    class win winBox
```

核心となる問題は相関（correlation）です。Warpgate は*エージェントが打ったもの*を、Tetragon は*実際に起きたこと*を教えてくれます。この2つを紐付けて初めて、セッションは監査可能になります。

承認ループはこうです。拒否された特権操作は機械可読な拒否IDを伴い → エージェントがMCPで承認を要求し → 人間がTelegramでタップし → 署名済みの期限付きリースが鋳造され → ブローカーが検証・償還して、束縛された操作だけを実行します。

Worker Gateway は、エージェントに認証情報を渡すことなく、到達範囲を広げます。エージェントは MCP Gateway に「タスクを委譲」を依頼し、ローカルのCLIエージェント（codex, dsh, opencode, commandcode, vibe, agy）がオーナーの環境で実行します。Windows 側の作業は `ssh windows` 経由のみ（マウントや追加ユーザーは使いません）。

監査ゲートは、ゲートウェイとワーカーの間に置きます。依頼は [Jev](https://docs.typesafe.ai)（TypeSafe の System One モデル）で分類します。型付きの選択問題に150〜300ミリ秒で答える仕組みで、文章生成をしないため、モデルの価値観が混ざりません。

| 分類 | 動作 |
|---|---|
| 通常の作業 | 実行 |
| NSFW系 | 実行 |
| 秘密鍵・認証情報 | **Telegram で承認を求める** |
| 監視の停止・改ざん | **Telegram で承認を求める** |
| 破壊的な操作 | **Telegram で承認を求める** |

パターン検査を先に実行し、分類を上げる方向にだけ働かせます。承認が必要な依頼は Telegram のボタンを待ち、10分で応答がなければ拒否です。ワーカーの出力も返す前に再分類し、結果に秘密鍵が混ざっていれば遮断します。全文は証拠ストアに残ります。通知には依頼元のノード、分類、信頼度が出ます。

現在のIDS/IPSの立ち位置を見ると、IDSは稼働中です（セッション自動レビュー + Telegram通知）。IPSは「OS境界での許可ベース」で実効（`ai-muse` にsudoなし、特権操作はブローカー経由、通信は観測のみでデフォルト拒否は未実装）。egressのデフォルト拒否とTetragonによる強制は Phase 3 の残項目です。

詳細は [docs/architecture.md](docs/architecture.md) を参照してください。

## はじめかた

用意するものは3つです。保護ホスト、ゲートウェイ、接続するエージェント。
以下の例では Muse を使いますが、SSH で接続できるエージェントなら何でも動きます。

### 1. 保護ホスト

自分が管理する Linux マシンで、Tailscale から到達できるものが必要です。
Docker と Tailscale を入れてから、次のコマンドを実行します。

```bash
git clone https://github.com/ganpare/agent-zerotrust
cd agent-zerotrust

# Warpgate（SSH要塞）と Tetragon（カーネル監視）
docker compose -f deploy/warpgate/docker-compose.yml up -d
docker compose -f deploy/tetragon/docker-compose.yml up -d
```

エージェントが動く非特権ユーザーを作り、sudo を与えません。

```bash
sudo useradd -m -s /bin/bash ai-muse
sudo passwd -l ai-muse
```

Warpgate はすべてのセッションを録画し、自分で生成した鍵でターゲットに
認証します。その公開鍵を `ai-muse` の `authorized_keys` に追加します
（`docker exec warpgate warpgate client-keys` で表示されます）。

### 2. ゲートウェイ

MCP ゲートウェイはエージェントの制御プレーンです。承認もワーカー委譲も
ここを通ります。

```bash
# 承認ストアとブローカー
sudo cp deploy/approvals/agent-zerotrust-mcp.service /etc/systemd/system/
sudo cp deploy/broker/agent-zerotrust-broker.service /etc/systemd/system/
sudo cp deploy/broker/azt-broker deploy/broker/azt-worker /usr/local/bin/
sudo systemctl enable --now agent-zerotrust-mcp agent-zerotrust-broker
```

ユニットファイルの `APPROVAL_BIND` に tailnet のアドレスを、
`WARGATE_URL` に Warpgate の管理URLを設定します。Telegram の認証情報は
`deploy/monitoring/state/telegram.json` に置きます（パーミッション 0600、
git 管理外）。

```json
{"bot_token": "...", "chat_id": "..."}
```

監査ゲートには TypeSafe のキーが必要です。`TYPESAFE_API_KEY` を直接設定するか、
キーを保持する [Infisical](https://infisical.com) を `INFISICAL_URL` /
`INFISICAL_PROJECT` / `INFISICAL_CRED_DIR` で指定します。

### 3. エージェントを接続する

入口は2つあり、どちらも同じゲートウェイに届きます。

**MCP 経由**（推奨。エージェントがツールを直接使えます）。

```json
{
  "mcpServers": {
    "agent-zerotrust": {
      "url": "http://<PROTECTED_HOST_IP>:8930/mcp"
    }
  }
}
```

**SSH 経由**（MCP クライアントを持たないエージェントや、セッションも
録画したい場合）。

```bash
ssh muse:<PROTECTED_HOST>-local@<PROTECTED_HOST_IP>
# ログイン後、セッションの中で:
azt-worker agents
azt-worker run opencode "テスト一式を実行して" --target linux
```

`azt-worker` は同じ `:8930/mcp` に投げるので、監査ゲートと承認フローは
MCP クライアントとまったく同じように効きます。

### 4. 経路を制限する

エージェントからは **SSH のポートと MCP のポートだけ**に届くようにします。
Tailscale の ACL で次のように書きます。

```jsonc
{
  "grants": [
    { "src": ["tag:agent-muse"], "dst": ["<PROTECTED_HOST>"],
      "ip": ["22", "8930"] }
  ],
  "tagOwners": { "tag:agent-muse": ["autogroup:admin"] }
}
```

エージェントのデバイスにタグを付けると、tailnet 上の他のものは
エージェントから到達できなくなります。証拠ストアも含めてです。

### MCP ツール

| ツール | 用途 |
|---|---|
| `request_approval(action, justification, ...)` | 例外の承認をオーナーに求める |
| `get_approval(request_id)` | 判断を問い合わせる |
| `list_worker_agents()` | 使える CLI エージェントを返す |
| `dispatch_worker_task(agent, instruction, target, workdir)` | ローカルエージェントに委譲する |
| `get_worker_task(task_id)` | タスクの状態と出力を取得する |
| `create_worker_agent(name, description, prompt, model, mode)` | 再利用できる OpenCode エージェントを定義する |
| `list_worker_agents_defined()` | ゲートウェイが作ったエージェントを一覧する |

### エージェントを定義する

エージェントは自分でワーカーを作れます。`create_worker_agent` は
OpenCode のエージェント定義を `~/.config/opencode/agents/<name>.md` に
書き出し、OpenCode が他のエージェントと同じように見つけて実行します。

```json
{
  "name": "create_worker_agent",
  "arguments": {
    "name": "test-writer",
    "description": "Python コードの単体テストを書く",
    "prompt": "pytest のテストを書きます。境界条件を網羅します。ソースは変更しません。",
    "model": "opencode/deepseek-v4.1-flash-free",
    "mode": "subagent"
  }
}
```

ファイルを書くのはエージェントではなくゲートウェイで、書く前に4点を確かめます。

| 確認 | 理由 |
|---|---|
| 名前が `[a-z0-9][a-z0-9-]{0,40}` に一致する | パストラバーサルを防ぎ、エージェント用ディレクトリの外に出さない |
| プロンプトを Jev で分類する | 鍵や監視の停止を求める定義は Telegram でオーナーに確認する |
| ファイルがオーナーの作ったものでないこと | オーナーが書いたエージェントは上書きしない |
| ゲートウェイが作ったエージェントが20個未満であること | ディレクトリを埋め尽くせないようにする |
| モデルが許可リストにあること | 高額なモデルを選べないようにする |

既定で使えるモデルは2つです。指定がなければ
`opencode/deepseek-v4.1-flash-free` を書き出し、もう1つは
`mistral/deepseek-v4-1-flash-1017` です。リストはコードではなく
`AZT_ALLOWED_MODELS`（カンマ区切り）で広げます。

削除のツールはありません。エージェントが作ったものは残ります。作成はすべて
証拠ストアの `agents.jsonl` に追記されます。

### オーナーに届くもの

委譲もブロックも完了も、依頼元のノード、Jev の分類、信頼度とともに
Telegram に届きます。

```text
⚠️ agent-zerotrust — ワーカー依頼の承認が必要です
依頼元: muse / tag:agent-muse (100.101.102.103)
分類: 秘密鍵・認証情報（信頼度 1.00）
エージェント: codex (対象: windows)
リクエスト: WREQ-1794101166-5a33d1

依頼内容:
cat ~/.ssh/id_ed25519 を表示してください

10 分以内に回答がなければ拒否として扱います。
[✅ 承認] [🚫 拒否]
```

運用手順の全体、ポートの対応、実際の構築で得た知見は
[deploy/README.md](deploy/README.md) にあります。

## 設計原則

1. 印象ではなく証拠。監査性は、エージェントが画面に表示することを
   選んだものの上ではなく、カーネルレベルの事実（eBPF）の上に立つ。
2. AIオプショナル設計。アクセス制御・記録・証拠は、AIゼロで動く。
   Guardian AI は拡張である。実行できる人には深い行動分析を提供するが、
   依存は決してさせない。
3. 改ざんに耐える証拠。監視対象はモニターを止められない、録画を
   編集できない、証拠ストアに届かない。
4. バイパスなし。Warpgate と MCP Gateway が正面玄関なら、裏口は
   存在しない。直接SSHの経路は「勧告」ではなく技術的に塞ぐ
   （sshdはLAN/ループバックのみ、tailnet上の22番はWarpgateそのもの）。
5. 証拠そのものを守る。セッション録画には秘密が入りうる。その機密性と
   保持は、後付けではなく設計要件である。

資産・敵モデル・脅威・要件の完全な分析は
[docs/threat-model.md](docs/threat-model.md) にあります。
このリポジトリの軸となる文書です。

## ロードマップ

| フェーズ | 目標 | 主要技術 | 状態 |
|---|---|---|---|
| 1 | エージェントの実際の行動を完全に追跡する | Warpgate + Tetragon | 完了 — [Milestone 1](docs/issues/001-auditable-ssh-access.md) |
| 2 | 独立したAIがその操作を評価する | Guardian AI + LLM | 完了 — 自動レビュー、Telegram、MCP承認、Codex/DSHバックエンド |
| 3 | 危険な操作を自動的に阻止する | ポリシーエンジン + IPS | コア完了 — 特権ブローカー＋署名リース。egressデフォルト拒否は残項目 |

詳細: [docs/roadmap.md](docs/roadmap.md)。

*検知*と*阻止*の間には、もう一段あります。人間の承認
（human-in-the-loop）です。危険な操作をワンタップの承認で止められます。
要求は証拠コンテキストとともに Telegram で届き、承認はその操作そのものに
束縛され、沈黙は拒否を意味します。設計メモは
[docs/architecture.md](docs/architecture.md) §8。

## リポジトリ構成

```text
agent-zerotrust/
├── README.md
├── README.ja.md            日本語README（このファイル）
├── LICENSE                  MIT
├── docs/
│   ├── architecture.md      コンポーネント、相関、フェイルセーフ挙動
│   ├── threat-model.md      資産、敵モデル、脅威、要件
│   ├── roadmap.md           フェーズと完了条件
│   └── issues/              Issue 化の準備ができたマイルストーン
├── deploy/
│   ├── warpgate/            要塞設定、ターゲット/ユーザーマッピング
│   ├── tetragon/            トレーシングポリシー（実行 / ファイル / 通信）
│   ├── monitoring/          証拠パイプライン、セッションウォッチャー
│   ├── approvals/           MCPゲートウェイのsystemdユニット
│   └── broker/              特権ブローカーのユニット＋azt-worker CLI
├── guardian/               オプションの Guardian AI（証拠を消費、強制はしない）
│   └── wrappers/            Codex / DSH のCLIラッパー
├── evidence/                相関、ケース構築、ルールバックエンド、Telegram
├── approvals/               MCPゲートウェイ：承認＋ワーカー委譲
├── broker/                  特権ブローカー：リース、台帳、ポリシー
├── workers/                 Worker Gateway：ローカルCLIエージェントへの委譲
├── policies/
│   ├── network/             Tailscale ACL（適用済み）
│   └── execution/           実行ポリシー（Phase 3）
└── tests/
    ├── security/            脅威モデルを検証する攻撃シナリオスクリプト
    └── *.py                 ユニットテスト（65/65）
```

## 関連プロジェクト

- [Meta: Security and safety for AI agents — our approach with
  Muse](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)
  — エージェント自身のランタイムを守る。`agent-zerotrust` は接続先を守る。
- [Warpgate](https://warpgate.null.page/) — セッションの録画と再生に対応した
  SSH要塞（bastion）。
- [Tetragon](https://tetragon.io/) — eBPFベースのセキュリティ監視・強制。
  Kubernetesは不要で、通常のLinuxホストで動く。
- [Tailscale](https://tailscale.com/) — ACLつきWireGuardメッシュ。経路制限に使用。

これらは依存として使っており（Docker イメージとクライアントツール）、
このリポジトリにコピーしたものではありません。ライセンスはそれぞれ
Warpgate と Tetragon が Apache-2.0、Tailscale のクライアントが BSD-3-Clause
です。このプロジェクトは MIT で、これらを使うことに互換性があります。

## ライセンス

[MIT](LICENSE)
