# CVE Watch

指定したキーワード（`linux kernel`, `php`, `symfony`, `postgresql`, `nginx` など）に
関連する脆弱性を **NVD (National Vulnerability Database) API 2.0** から定期取得し、

- Web 画面で一覧・検索・ステータス管理
- 新しい脆弱性を **Slack / Google Chat** に Webhook 通知

する軽量サービスです。SQLite + 単一プロセス（FastAPI）で動作し、Docker Compose 一発で起動します。

---

## 構成

```
app/
  main.py        FastAPI 本体 + 静的ファイル配信 + 起動処理(lifespan)
  config.py      環境変数による設定
  database.py    SQLite エンジン / セッション
  models.py      テーブル定義 (watches, cves, cve_keywords, meta)
  repository.py  DB 操作 (upsert / meta / watches)
  nvd.py         NVD API 2.0 クライアント (キーワード検索・ページング・パース)
  poller.py      取得→保存→新規検出→通知 の中核ロジック
  scheduler.py   APScheduler による定期実行
  notifier.py    Slack / Google Chat への Webhook 送信
  routes/        REST API (cves / watches / system)
  static/        Web UI (バニラ JS の SPA)
```

データ（SQLite ファイル）は `./data/` に永続化されます。

---

## セットアップ (AlmaLinux 9 + Docker Compose)

### 1. Docker を入れる

```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 2. 設定ファイルを用意

```bash
cp .env.example .env
vi .env
```

最低限、通知先の Webhook URL を設定してください（使う方だけでOK）。
NVD の API キー（無料）を入れるとレート制限が緩くなり、取得が大幅に速くなります
→ https://nvd.nist.gov/developers/request-an-api-key

```dotenv
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
GOOGLE_CHAT_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...
PUBLIC_BASE_URL=http://your-server:8000
```

### 3. 起動

```bash
docker compose up -d --build
```

ブラウザで `http://<サーバー>:8000` を開きます。

> 初回起動時は `INITIAL_LOOKBACK_DAYS`（既定 7 日）分の CVE を **通知なしで** 取り込み（シード）します。
> 2 回目以降のポーリングで見つかった新規 CVE のみ通知されます。

---

## 使い方

### 監視ワード
画面上部「監視ワード」タブで追加・有効/無効・削除ができます。
NVD のキーワード検索に渡されます（複数語はスペース区切り＝AND 検索、例: `linux kernel`）。

### 脆弱性一覧
- ステータスチップ / ステータス・ワード・深刻度・フリーワードで絞り込み
- 行をクリックすると詳細（説明・参照リンク・メモ編集）
- 各行のプルダウンでステータスを即時変更

### ステータス
`新規 / 要対応 / 対応中 / 対応済み / 無視 / 関係ない`

### 手動チェック
右上「今すぐチェック」でその場でポーリングを実行できます。

---

## 通知

新しい CVE が見つかると、設定済みのチャンネルに送信されます。

- **Slack**: [Incoming Webhook](https://api.slack.com/messaging/webhooks) の URL を `SLACK_WEBHOOK_URL` に設定
- **Google Chat**: スペースの [Webhook](https://developers.google.com/workspace/chat/quickstart/webhooks) URL を `GOOGLE_CHAT_WEBHOOK_URL` に設定

`NOTIFY_MIN_CVSS` で通知する CVSS スコアの下限を設定できます（既定 0 = すべて通知）。

---

## 設定一覧（.env）

| 変数 | 既定 | 説明 |
|------|------|------|
| `NVD_API_KEY` | (空) | NVD API キー。あるとレート制限が 5→50 req/30s に緩和 |
| `POLL_INTERVAL_MINUTES` | `60` | ポーリング間隔（分） |
| `INITIAL_LOOKBACK_DAYS` | `7` | 初回シードで遡る日数（通知なし） |
| `SLACK_WEBHOOK_URL` | (空) | Slack 通知先 |
| `GOOGLE_CHAT_WEBHOOK_URL` | (空) | Google Chat 通知先 |
| `NOTIFY_MIN_CVSS` | `0.0` | 通知する CVSS の下限 |
| `PUBLIC_BASE_URL` | `http://localhost:8000` | 通知内「管理画面」リンクの基底 URL |
| `DEFAULT_WATCHES` | `linux kernel,php,symfony,postgresql,nginx` | 初回のみ投入される監視ワード |
| `DATABASE_URL` | `sqlite:///./data/cve.db` | DB 接続先 |

---

## API（参考）

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/stats` | 件数サマリ・ステータス定義・最終チェック時刻 |
| GET | `/api/cves` | 一覧（`status,keyword,severity,q,sort,limit,offset`） |
| GET | `/api/cves/{id}` | 詳細 |
| PATCH | `/api/cves/{id}` | `{status, note}` の更新 |
| GET/POST | `/api/watches` | 監視ワード 取得/追加 |
| PATCH/DELETE | `/api/watches/{id}` | 有効切替 / 削除 |
| POST | `/api/poll` | 手動ポーリング（バックグラウンド実行） |

OpenAPI ドキュメントは `/docs` で確認できます。

---

## 開発（ローカル, Python 3.11+）

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
# オフラインのスモークテスト:
.venv/bin/python smoke_test.py
```
