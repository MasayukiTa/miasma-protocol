# macOS → Windows 大容量転送テスト手順書

対象ブランチ: `work/resumable-protected-transfer`。設計と根拠は
[`protected-resumable-transfer-plan.md`](protected-resumable-transfer-plan.md)、実測値はその §6。

**このテストが初の「別々の2台のあいだの転送」です。** これまでの検証は全て1台のマシン上(loopback)
でした。Mac で `miasma` がビルドできて動くかどうかも、まだ誰も確かめていません(CI が macOS で
ビルドするのは core・ffi・wasm だけで、CLI は含まれません)。下の手順は、その未確認部分を
小さく潰してから大きくするように並べてあります。**途中のどこかで失敗したら、そこで止めて報告してください。**

## 0. 何を確かめるテストか

| 要件 | どう確かめるか |
|---|---|
| 分割され、各ピースが個別の ID を持つ | 受信側が全ピースを manifest の ID と照合する(`pieces_rejected` が 0 のはず) |
| MID とパスワードの両方で縛る | パスワード無し/誤りは、**データを1つも取得する前に**拒否される |
| 冗長度を下げて試す | `redundancy-bench` と、実転送で `k/n` を変えて比較する |
| 進捗が分かる | `network-get` / `network-publish` の進捗行、`miasma transfers` |
| 再開できる | 強制終了(kill -9)しても、同じコマンドを再実行すれば続きから |
| 速度 | 各段階で MB/s を記録し、外挿する(**実測していない値は信用しない**) |

## 1. 前提とディスク計算

- **送信側 = Mac**(外付け SSD 2 TB)、**受信側 = Windows**。受信側が送信側に接続します
  (Windows から Mac へ)。したがって**開ける必要があるのは Mac の受信ポートだけ**です。
- 送信側は、**受信が終わるまで起動したまま**にしてください(この構成では他のピアはシェアを
  預からないので、全シェアは送信側にしかありません)。
- 両側を**同じコミット**でビルドします: `git log -1 --format=%H` が一致すること。
  (以前の配布版 `0.3.1` とは互換性を確認していません。)

必要量(`k=10` のとき。**計算式は `estimated_local_share_storage_bytes` と同じ**):

| ファイル | k/n | 保存クォータ(MiB) | 送信側の空き(元ファイル込み) | セグメント数 |
|---|---|---|---|---|
| 256 MiB | 10/12 | 308 | 0.55 GiB | 4 |
| 4 GiB | 10/12 | 4,922 | 8.81 GiB | 64 |
| 20 GiB | 10/12 | 24,607 | 44.03 GiB | 320 |
| 100 GiB | 10/10 | 102,526 | 200.12 GiB | 1,600 |
| 100 GiB | **10/12** | **123,031** | **220.15 GiB** | 1,600 |
| 100 GiB | 10/20(既定) | 205,051 | 300.24 GiB | 1,600 |

- **受信側**: 出力ファイルと同じボリュームに、ファイルサイズ + 数 MB(`.part` は完成時に
  リネームされるだけなので、追加の 1 倍は要りません)。100 GiB なら 100 GiB 以上の空き。
- 既定の保存クォータは **10,240 MiB** です。20 GiB 以上では**必ず上げてください**(足りないと
  公開は何も始まる前に拒否されます)。設定は**フラグ形式**です:

```bash
miasma --data-dir /Volumes/SSD/miasma-data config --key storage.quota_mb --value 123031
miasma --data-dir /Volumes/SSD/miasma-data config --key storage.quota_mb      # 確認
```

## 2. 手順

### 2-1. Mac でビルドして自己診断する

```bash
git clone https://github.com/MasayukiTa/miasma-protocol && cd miasma-protocol
git checkout work/resumable-protected-transfer
cargo build --release -p miasma-cli          # 初の macOS ビルド。失敗したらここで止めて最初のエラーを報告
./target/release/miasma --help
scripts/transfer-e2e.sh                       # 1台の中で 2 ノードを立てて 8 項目確認。PASS が出ること
```

`transfer-e2e.sh` は、パスワード付き公開 → 誤り/無しのパスワードの拒否 → **受信側デーモンを
kill -9** → 再起動 → 再開 → SHA256 一致、さらに**送信側デーモンを kill -9** → 再開、までを確認します。

### 2-1b. Rust を入れずに、ビルド済みを受け取る場合(Apple シリコンの Mac)

Mac の持ち主に Rust を入れてもらうのは負担が大きいので、CI(`macos-cli-transfer` ジョブ)が
リリースビルドを作ります。PR の Actions 画面 → そのジョブ → Artifacts の `miasma-macos-arm64`
(14 日で消えます。ダウンロードには GitHub ログインが必要なので、**あなたが取って相手に渡します**)。
中身は `miasma-macos.tar.gz`(`miasma`、`miasma-desktop`、`transfer-e2e.sh`、この手順書)。
作った CI 上で `transfer-e2e.sh` が PASS したバイナリです(実際に相手の Mac で動くかは別。下の確認 1〜3 で確かめる)。

相手の Mac で:

```bash
cd ~/Downloads
shasum -a 256 miasma-macos.tar.gz           # こちらが控えた値(CI のログに出る)と一致すること
tar -xzf miasma-macos.tar.gz && cd miasma-macos
xattr -dr com.apple.quarantine .            # 署名なしのため、ダウンロード印を外す(初回だけ)
./miasma --help                              # 1) 起動すること
./transfer-e2e.sh --cli ./miasma             # 2) 1台の中で 2 ノード。PASS が出ること
```

- 「開発元を検証できない」と出たら、上の `xattr` を実行していません(または、システム設定 → プライバシーとセキュリティ → 「このまま開く」)。
- 初めて `daemon` を起動すると、**着信接続を許可するか**のダイアログが出ます。**許可**します。
- **外付け SSD** を使うとき、ターミナルが外付けドライブに触る許可を求められたら許可します(システム設定 → プライバシーとセキュリティ → ファイルとフォルダ / フルディスクアクセス)。
- GUI(`./miasma-desktop`)も同じフォルダにあります。`.app` ではないので、ターミナルから起動します。
- Intel の Mac では動きません(アーム版のみ)。相手の Mac が Intel かは `uname -m` で確認(`arm64` ならよい)。

### 2-2. Windows でも同じ自己診断をする

```powershell
cargo build --release -p miasma-cli
powershell -ExecutionPolicy Bypass -File scripts\transfer-e2e.ps1
```

(Windows の C: の空きが少ない場合は `$env:CARGO_TARGET_DIR` を別ドライブにします。)

### 2-3. 冗長度を測る(Mac のリリースビルド)

```bash
mkdir -p /Volumes/SSD/bench
./target/release/miasma redundancy-bench --size-mib 1024 --store-dir /Volumes/SSD/bench
rm -rf /Volumes/SSD/bench
```

読み方: **「保存倍率(実測)」と「損失耐性」はどのマシンでも正確**です。**MiB/s は Mac のリリース
ビルドで測った値だけ**意味があります。`--store-dir` を付けると外付け SSD への書き込みと保存時暗号化も
含めた速度が出ます。この表を見て `k/n` を選んでください。

参考(このリポジトリの開発機での実測。倍率のみ有効): 10/10 → 1.000×、10/11 → 1.100×、
10/12 → 1.200×、10/15 → 1.500×、10/20 → 2.000×。

> **10/10(冗長ゼロ)について。** 1対1の転送では、パリティが守るのは送信側自身の保存ファイルの
> 破損だけです(通信の誤りは、ピース ID の照合と再取得で扱います)。ただし 10/10 では、シェアが
> 1つでも壊れると**そのセグメントは復元できません**(その場合は `paused: only 9 of 10 valid pieces`
> のように止まり、再公開が必要)。最初は **10/12** を勧めます。

### 2-4. 2台をつなぐ

```bash
# --- Mac (送信側) ---
D=/Volumes/SSD/miasma-data
miasma --data-dir $D init --listen-addr /ip4/0.0.0.0/tcp/4001
miasma --data-dir $D config --key storage.quota_mb --value <表の保存クォータ>
miasma --data-dir $D daemon                   # 前面で動かす。別ターミナルで以降を実行
miasma --data-dir $D status                   # "Listen addr:" に LAN の IP と PeerId が出る
```

```powershell
# --- Windows (受信側) ---
$D = "D:\miasma-data"
miasma --data-dir $D init
miasma --data-dir $D daemon --bootstrap /ip4/<MacのLAN IP>/tcp/4001/p2p/<MacのPeerId>
miasma --data-dir $D status                   # peer が 1 になること
```

- macOS は初回に「受信接続を許可しますか」と聞きます。**許可**してください。
- 有線 LAN を推奨します。**先に生のLAN速度を測る**と、上限が分かります(`iperf3 -s` を Mac、
  `iperf3 -c <Mac>` を Windows)。
- mDNS(同一 LAN の自動発見)が社内 LAN や VPN で止められている場合は、上の `--bootstrap` で明示します。
- つながらない場合は、Mac 側の `status` の peer 数、両側の `daemon` のログ、ファイアウォールを確認。
  **Windows→Mac が通れば十分**です(受信側が接続する側)。

### 2-5. 段階を上げて転送する(256 MiB → 4 GiB → 20 GiB → 100 GiB)

各段階で同じことを行い、記録表(§3)を埋めます。**前の段階が通ってから次へ。**

```bash
# --- Mac: ダミーファイルとパスワード ---
head -c $((4*1024*1024*1024)) /dev/urandom > /Volumes/SSD/test-4g.bin     # 段階に合わせてサイズを変える
printf '%s\n' 'ここに強いパスワード' > /Volumes/SSD/pw.txt
shasum -a 256 /Volumes/SSD/test-4g.bin

# --- Mac: 公開(進捗行が出る。完了時に MID と平均速度が出る) ---
miasma --data-dir $D network-publish /Volumes/SSD/test-4g.bin \
    --data-shards 10 --total-shards 12 --password-file /Volumes/SSD/pw.txt
```

```powershell
# --- Windows: パスワードファイルを安全な手段で渡してから ---
miasma --data-dir $D network-get <MID> -o D:\recv\test-4g.bin --password-file D:\pw.txt
Get-FileHash D:\recv\test-4g.bin -Algorithm SHA256        # Mac の値と一致すること
```

**中断ドリル(4 GiB の段階で必ず行う):**

1. 受信中に Ctrl-C → `miasma transfers` でデーモン側の転送が続いていることを確認。
2. 受信側デーモンを `kill -9`(Windows は `Stop-Process -Force`)→ 再起動 → 同じ `network-get` を
   再実行 → **`seg N/M` が 0 に戻らず、続きから**進むこと。最後に SHA256 一致。
3. **送信側**デーモンを受信中に落とす → 受信側は `paused: ... valid pieces` で止まる →
   送信側デーモンを再起動 → 同じ `network-get` で再開。
4. 公開中に送信側デーモンを落とす → 再起動 → 同じ `network-publish` で再開(元ファイルを
   変更していないこと)。

### 2-6. 逆方向(Windows → Mac、約 100 MB)

同じ手順を役割を入れ替えて行います。**Windows が送信側になるので、Windows の受信ポートを
Mac から届くようにしてください**(Windows Defender ファイアウォールの許可)。

### 2-7. 100 GiB

- 事前確認: 送信側の空き(表)、保存クォータ、受信側の空き 100 GiB 以上。
- 送信 Mac がスリープしないこと: `caffeinate -dimsu -w <daemonのPID>`。Windows も電源プランでスリープなし。
- 所要時間は、**20 GiB の段階で実測した MB/s** から `100 GiB / 実測値` で見積もってください。
- 止まったら(`paused: ...`)**同じコマンドを再実行するだけ**です。原因が空き容量なら、空けてから再実行。

## 3. 記録表(段階ごとに 1 行)

| 段階 | k/n | ハッシュ時間 | 公開: 所要 / 平均MB/s | 受信: 所要 / 平均MB/s | 受信の fetch / decode / write (ms) | rejected / retries | SHA256 一致 | 備考 |
|---|---|---|---|---|---|---|---|---|
| 256 MiB | | | | | | | | |
| 4 GiB | | | | | | | | |
| 20 GiB | | | | | | | | |
| 100 GiB | | | | | | | | |

進捗行の `(fetch X% decode Y% write Z%)` が、時間がどこに使われているかを示します
(送信は `store+push` と `dissolve`)。**fetch が支配的なら通信/ディスク読み出し、decode なら CPU、
write なら受信側ディスク**です。最初に測るべきはこの内訳です。

## 4. 既知の制約(実測・確認していないものを含む)

- **Mac ビルドは未確認**(§2-1 で確かめる)。CI は macOS で CLI をビルドしていません。
- **別々の2台の間の転送は、リポジトリ全体で初めて**です。
- **他のピアはシェアを預かりません**(預かり枠が本番で 0 で、設定項目がありません)。送信側が
  常にオンラインである必要があります。この修正は別件として計画書に記録済みです。
- **DHT レコードは 100 GiB で約 8 MB**(16.7 MB の上限に対して余裕あり。**シリアライズ後の大きさは
  テスト済みですが、実際の Kademlia が 8 MB のレコードを複製できるかは未確認**です)。
  `network-get` が「no record found」になる場合はここを疑い、報告してください。
- 保存の 1 回あたりの時間はストアの個数に比例して伸びます(デバッグビルドで 4,000 個 → 123 ms/回。
  リリースは未測定)。100 GiB(32,000 個)で公開が遅い場合は、この計測が該当します。
- **パスワードが縛るのは「暗号化」だけ**です。MID を知る人はシェアの暗号文を取得できますが、
  パスワード無しには復号できません。受信者のキーでの縛り(directed の ECDH)は入っていません。
- PoW admission のバイパス(既知の重大な未修正項目)は、この機能とは無関係に残っています。
  ベータ、未監査、機微データには使わないでください。
- 表示メッセージは現状**英語のみ**です(日本語化は依頼済み・保留)。

## 5. 困ったとき

| 症状 | 見るところ |
|---|---|
| `wrong password` | パスワードファイルの**改行だけが除かれ、空白は含まれます**。前後の空白に注意 |
| `this transfer is password-protected` | `--password-file` が必要 |
| `no record found for ... after 6 attempts` | 接続(`status` の peer 数)、送信側が起動中か、bootstrap、ファイアウォール |
| `paused: segment N: only X of 10 valid pieces` | 送信側が止まっている/届かない。復旧後に同じコマンドを再実行 |
| `paused: cannot write ...` | 受信側の空き容量。空けて再実行 |
| `publish requires approximately N MiB of owned-share quota` | `storage.quota_mb` を上げる(§1) |
| `source file changed while publishing` | 公開中に元ファイルが変更された。再度 `--restart` 付きで |
| 転送状況を見たい | `miasma transfers`(停止中のものも、前回のデーモンの分も出る) |
| 止めたい | `miasma transfer-cancel <MID>`(部分ファイルは残り、再開可能) |
| 最初からやり直したい | `network-get ... --restart` / `network-publish ... --restart` |
