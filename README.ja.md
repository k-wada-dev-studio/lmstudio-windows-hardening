# Windows Local AI Hardening

インストール済みの LM Studio とモデルを Windows 上でローカル利用し、外部通信を
可能な範囲で抑えるための、非公式 PowerShell スクリプト集です。

> **プレビュー版:** `0.1.0-preview` は静的テストと模擬動作テストを通していますが、
> Windows、LM Studio、GPU、Runtime の全組合せでは未検証です。最初は本番用途でない
> Windows アカウントで評価してください。

> **実機再試験が必要:** 2026-08-20 の試験で実モデルのロードと推論は成功しましたが、
> `lms daemon up` が起動しませんでした。その依存はコードから除去済みですが、共有フォルダを含む
> 改善後の完全試験は未実施です。詳細は[実機テスト報告](docs/LIVE-TEST-2026-08-20.md)を参照してください。

[English README](README.md)

## いちばん簡単な使い方

配布管理者が共有フォルダ上の **1つだけのGGUF** をセットアップ専用の非公開配布設定へ
登録しておきます。利用者は事前に LM Studio と対応 Runtime をインストールしてください。
このプロジェクトはモデルや Runtime をダウンロードしません。

1. LM Studio を完全に終了します。
2. `1-Setup.cmd` をダブルクリックします。
3. Windows の管理者確認が表示されたら、モデルリンク登録（`ProjectFirewall = 'ON'` ではFirewall設定も含む）のために許可します。
4. 完了後、普段は `2-Start-Secure.cmd` をダブルクリックして起動します。

セットアップが共有GGUFをシンボリックリンクとして自動登録し、最初の安全起動がその `modelKey` を検出・保存します。
利用者がモデル名を調べたり、LM Studio の「My Models」やJSON設定を操作したりする必要はありません。
別のローカル LLM がある場合は、最初の安全起動で誤選択せず停止します。確定後の状態には `modelKey` とパス照合用
SHA-256だけを保存し、共有フォルダのパスそのものは保存しません。

元へ戻すときは LM Studio を終了して `3-Restore.cmd` をダブルクリックします。パッケージ自体を
確認したい場合は `Check-Package.cmd` を使用できます。

これらの `.cmd` は同梱されたローカルの `.ps1` だけを起動します。PowerShellの
`ExecutionPolicy Bypass` はその1回のプロセスだけに適用され、PC全体の実行ポリシーは変更しません。

## 何をするものか

防御を次の2層に分けています。

1. **ネットワーク保護の管理方法を明示します。** 既定の `ProjectFirewall = 'ON'` では、Windows
   Firewallを強制境界として、LM StudioのGUI、CLI/daemon、検出したRuntime実行ファイルごとに
   ループバック以外のIPv4/IPv6通信を送受信とも遮断します。`ProjectFirewall = 'OFF'` では、会社側の
   Firewall/EDR/ネットワークポリシーへ委任し、本プロジェクトの規則を作成・監査しません。
2. **LM Studio の JSON 設定を補助防御にします。** 通信、開発プラグイン、MCP、自動ロードに
   関係する一部項目だけを安全側へ戻し、無関係な項目は保持します。公開APIサーバーの
   自動起動を無効化し、明示的に起動する場合の保存済み待受け先も `127.0.0.1` に固定します。

初期セットアップでは共有モデルリンク、選択したネットワーク管理状態、JSON保護を準備します。最初の安全起動時に
GUI経由でモデルと互換Runtimeを検証・確定し、他モデルを拒否して承認モデルだけをロードします。
モデル、Runtime、アプリをスクリプトがダウンロードすることはありません。

LM Studio 公式資料では、ダウンロード済みモデルによるチャット、ローカル文書チャット、
ローカルサーバーはオフライン動作できる一方、検索、ダウンロード、Runtime 取得、更新確認は
通信を必要とすると説明されています。公式の
[オフライン利用](https://lmstudio.ai/docs/app/offline) と
[CLI資料](https://lmstudio.ai/docs/cli)も確認してください。

## 前提条件

- Windows 10 または 11
- `ProjectFirewall = 'ON'`ではWindows Firewallが有効、`'OFF'`では配布責任者が会社側の保護を別途確認済み
- Windows PowerShell 5.1
- LM Studio を一度は初期化済み
- 共有フォルダ上の1つのGGUFへアクセス可能で、互換 Runtime をインストール済み
- `lms` CLI が利用可能
- セットアップと復元の実行中は LM Studio と `llmster` を完全終了

管理者確認が必要なのは短いモデルリンク登録と、本プロジェクトのFirewall規則をON/OFFする処理だけです。メインのスクリプトは、LM Studio を
使う通常ユーザーとして実行してください。

### 配布管理者が1度だけ行う準備

`config\deployment.local.psd1.example` を `config\deployment.local.psd1` としてコピーし、
`ModelSourcePath` に共有フォルダまたはGGUFファイルのUNCパスを設定します。さらに `ProjectFirewall` を、
本プロジェクトで規則を管理する `'ON'`（既定・推奨）か、会社側へ委任する
`'OFF'` のどちらかに設定します。`'OFF'` はWindows Firewall本体を無効にする指定ではなく、
配布責任者が別の仕組みで通信制御を確認するという明示的な委任です。フォルダ指定では、
その直下にGGUFが1つだけ必要です。このローカル設定は `.gitignore` の対象なので、共有先の名前を
GitHubへ公開しません。設定済みパッケージを受け取る利用者には、この作業は不要です。

セットアップ済みPCでも、LM Studioを終了して `ProjectFirewall` の `'ON'` / `'OFF'` を変更し、
`1-Setup.cmd` を再実行すれば切り替えられます。`'OFF'` への切替時は、本プロジェクトが以前作成した
`LM Studio Secure Local-Only` グループの規則だけを削除し、Windows Firewall本体や会社側の規則には触れません。

## PowerShellから実行する場合

1. [脅威モデル](docs/THREAT-MODEL.md)と3本のスクリプトを確認します。
2. 通常のインターネット接続が使える段階で、信頼できる公式配布元から LM Studio と対応
   Runtime を準備し、配布管理者が非公開配布設定を作成します。
3. LM Studio と `llmster` を完全に終了します。
4. 初期設定を実行します。共有GGUFの登録と `modelKey` の取得は自動です。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Setup-LMStudio.ps1
```

上級者がモデルを明示する場合だけ、正確な `modelKey` を指定できます。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Setup-LMStudio.ps1 `
    -AllowedModel 'publisher/model-key'
```

5. 通常利用では安全起動スクリプトだけから起動します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Start-LMStudio-Secure.ps1
```

6. JSON を検証済みの初期設定前バックアップへ戻す場合は復元スクリプトを使います。
   安全側の既定動作では、このプロジェクトのFirewall規則を残します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Restore-LMStudio.ps1
```

Firewallも明示的に削除する完全解除だけ、PowerShellから `-RemoveFirewall` を指定します。
この操作後は本プロジェクトによる外部通信遮断がなくなります。LM Studio の更新や
モデル変更の前には[運用手順](docs/OPERATIONS.md)を確認してください。`ProjectFirewall = 'OFF'`では、
復元スクリプトも会社・組織側のFirewall/EDR/ネットワークポリシーを変更しません。

## どのファイルが作成・変更されるか

`secure-setup` フォルダとその中身は **LM Studio 標準ではなく、本プロジェクトが作成する
専用管理領域**です。

| 場所 | 所有・作成元 | このプロジェクトでの扱い |
|---|---|---|
| `%USERPROFILE%\.lmstudio\settings.json` | LM Studio標準 | 対象項目だけ変更。変更前にバックアップ |
| `%USERPROFILE%\.lmstudio\mcp.json` | LM Studio標準 | `mcpServers`を空にする。変更前にバックアップ |
| `%USERPROFILE%\.lmstudio\.internal\http-server-config.json` | LM Studio内部 | 存在する場合だけ、自動起動をOFF・待受け先をlocalhostへ変更。変更前にバックアップ |
| `config\deployment.local.psd1` | 配布管理者 | 共有モデルの場所。Git管理対象外で利用者は編集不要 |
| `%USERPROFILE%\.lmstudio\models\secure-deployment\` | 本プロジェクト | 共有GGUFを指す管理用シンボリックリンク |
| `%USERPROFILE%\.lmstudio\secure-setup\` | 本プロジェクト | 初回Setupで新規作成する専用領域 |
| `secure-setup\setup-state.json` | 本プロジェクト | Setup結果を保存。初回の安全起動成功後に許可モデル、パス照合用ハッシュ、Runtime検証結果を確定 |
| `secure-setup\last-launch.json` | 本プロジェクト | 最後に成功した安全起動の結果とパス照合用ハッシュを保存 |
| `secure-setup\logs\` | 本プロジェクト | Setup・起動・復元のログ |
| `secure-setup\backups\` | 本プロジェクト | JSON変更前と復元前のバックアップ |
| Firewallグループ `LM Studio Secure Local-Only` | 本プロジェクト | `ProjectFirewall = 'ON'`の場合だけ作成し、対象実行ファイルの非ループバック通信を遮断 |

`setup-state.json` は手作業で編集しないでください。削除・破損・内容不一致がある場合、安全起動は
LM Studioを起動せず停止します。復旧方法は Setup の再実行です。バックアップやログには、以前の
設定、ローカルパス、モデル名が含まれる可能性があるため、GitHubや公開Issueへ添付しないでください。

共有フォルダ利用ではモデル読込みのための LAN/SMB 通信が必要です。本プロジェクトの Firewall
規則は検出した LM Studio 関連実行ファイルを対象にしており、Windows 自体が行うファイル共有通信
まで遮断するものではありません。厳密にネットワークを完全遮断する用途ではローカルコピーが必要
です。共有フォルダの権限と接続性は、実際のPCで安全起動後に確認してください。

## 安全側の動作

- セットアップは再実行でき、共有モデルリンク、JSON保護、および選択したネットワーク管理方法の記録が成功するまでSetup完了状態にしません。
- モデルとRuntimeは初回の安全起動で検証し、承認モデルのロード成功後にだけ検証済み状態へ更新します。
- JSON 変更は検証済み一時ファイル、原子的置換、バックアップ、ロールバックを使います。
- `ProjectFirewall = 'ON'`の安全起動は Firewall 規則の欠落・無効化・古い状態に加え、適用プロファイル、プロトコル、
  ポート、対象サービスの不完全な制限も拒否し、新しい実行ファイルを検知します。
- `ProjectFirewall = 'ON'`のFirewall完全監査はSetup時と、その後24時間ごとに行います。24時間以内の起動では、直近の
  完全監査記録と実行ファイル構成を照合し、毎回の長い管理者監査を省略します。
- `ProjectFirewall = 'OFF'`では会社側ポリシーを検証済みとは表示せず、毎回警告を出します。LM Studio関連の
  実行ファイル構成が変わった場合は、どちらのモードでも安全起動を停止します。
- 安全起動はGUI準備後とモデルロード後に実際のTCP待受けを検査し、LM Studio関連プロセスが
  `0.0.0.0`、`::`、LANアドレスなどlocalhost以外で待受けていれば起動を失敗扱いにします。
- 復元は同じ LM Studio プロファイル用に作成された「初回セットアップ時バックアップ」だけを
  ハッシュ検証して受け入れ、変更前に別の復元用安全バックアップを作ります。関連Runtimeが
  動作中の場合は復元しません。既定ではFirewall規則を保持し、完全解除は明示指定時だけ行います。
- プロセス強制終了、ホスト全体の Firewall 既定値変更、ダウンロード、追加 LLM の黙認はしません。
- ログ、バックアップ、状態は `%USERPROFILE%\.lmstudio\secure-setup` 配下に置きます。

## 重要な限界

これは強化用の自動化であり、サンドボックスや EDR ではありません。

- ローカル管理者、カーネルレベルのソフトウェア、別プロセスによる回避は防げません。
- Firewall 規則は実行ファイルのパス単位です。LM Studio や Runtime 更新後は Setup を再実行して
  ください。未登録の新規実行ファイルがあれば安全起動は拒否します。
- LM Studio の JSON スキーマは内部仕様で、変更される可能性があります。このため JSON は
  補助防御として扱い、`ProjectFirewall = 'ON'`ではFirewall、`'OFF'`では組織側の対策を強制境界とします。
- ループバック通信は許可されます。同一 PC の別プロセスが、認証なしのローカルサービスへ
  接続できる可能性は残ります。
- 公開APIサーバー設定はLM Studioの内部JSON仕様です。バージョン変更で項目が変わっても、
  起動後の実待受け検査とネットワーク境界が別層として機能します。
- 他アプリ、未検出プラグイン、モデル管理ツール、ユーザー作成スクリプトは対象外です。
- 組織管理ポリシーでローカルFirewall規則が無効な場合、`ProjectFirewall = 'ON'`は保護済みと誤認させず停止します。
  会社側で通信を管理するPCは、配布責任者が実効性を確認したうえで `ProjectFirewall = 'OFF'` を選択してください。

よくある問題は[トラブルシューティング](docs/TROUBLESHOOTING.md)を参照してください。

## テスト

PowerShellを使わない場合は `Check-Package.cmd` をダブルクリックします。

```powershell
powershell.exe -NoProfile -File .\tests\Test-Static.ps1
powershell.exe -NoProfile -File .\tests\Test-Behavior.ps1
```

テストは実際の LM Studio プロファイルや Windows Firewall を変更しません。正式リリース前には、
[運用手順](docs/OPERATIONS.md)のチェックリストを使い、使い捨て可能な Windows 環境で実機検証が
必要です。

## プロジェクトの位置付け

本プロジェクトは独立した非公式プロジェクトで、LM Studio または Element Labs, Inc. との提携・
承認関係はありません。詳細は [NOTICE](NOTICE.md) を参照してください。
[MIT License](LICENSE) で提供します。
