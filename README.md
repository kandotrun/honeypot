# honeypot

さくらVPS（133.125.35.179）で稼働するハニーポット群のソース一式。
攻撃を受け止めて観測するためのもので、実サービスは含まれない。

## 構成

| ディレクトリ | 内容 | 公開面 |
|---|---|---|
| `cowrie/` | Cowrie（SSH/Telnet ハニーポット）の compose・設定・外向き遮断スクリプト・集計 | 公開IP 22/23 |
| `opencanary/` | OpenCanary（FTP/HTTP系/MySQL/Redis/VNC 等の囮、自作イメージ） | 公開IP 21/8080/3306/1433/6379/5900/5060 |
| `wp-honeypot/` | 自作の軽量 WordPress 囮（stdlib のみ）。80/443 を担当し、攻撃者の行動を JSONL に記録 | 公開IP 80/443 |
| `status/` | 両センサーのログから status.json を生成するプロデューサと tailnet 限定の配信 | Tailscale のみ |
| `relay/` | status.json をオフィス LAN へ中継（kan-pi） | オフィス LAN |
| `ops/` | VPS へファイルを送る・コマンドを実行する補助スクリプト | - |

## 安全設計

- コンテナは read_only / cap_drop ALL / no-new-privileges / メモリ・pids 上限つき。
- 外向きの新規接続は `cowrie/block-outbound.sh`（DOCKER-USER + INPUT、cowrie-fw.service で永続化）で、公開宛て TCP 80/443 のみ許可。プライベート / CGNAT（tailnet）/ ループバック宛ては遮断。対象は cowrie（172.30.0.0/24）と canary 系（172.31.0.0/24）のサブネットで、wp-honeypot は canary のネットワークに参加して同じポリシーを受ける。
- 囮は認証を絶対に成功させない。返すコンテンツはすべて合成値で、実ファイル・実在の秘密情報は含まない。
- 検体（Cowrie が取得したダウンロード）は VPS 上に隔離保存され、ここには含めない。

## 運用

- 日次サマリー: Muse の cron `cowrie-daily-report` が毎朝、前日分の3センサー分を集計して報告する（集計スクリプトは各ディレクトリの `summarize*.py`）。
- wp-honeypot は実トラフィックに合わせて10分間隔の改善ループ（cron `wp-honeypot-evolve`）で深化中。変更はこのリポジトリの main に積む。
- デプロイ先: VPS 上の `/opt/cowrie`、`/opt/opencanary`、`~/wp-honeypot`、`/opt/honeypot-status`。

## 含めていないもの

- ログ・検体・証明書の秘密鍵・パスワード類はコミットしない（`.gitignore` 参照）。
