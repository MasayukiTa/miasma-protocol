# 担当 1/5 結果: 既定 config からプライベート bootstrap を除去

worktree: C:/Users/M118A8586/AppData/Local/Temp/m365-companion/agents/offC (branch offline/C)

## コード変更（既に実装済みを確認。追加編集不要）

対象ファイル: `crates/miasma-core/src/config.rs`

- **既定 bootstrap リストは空**: `config.rs:1000` `bootstrap_peers: vec![]`（`NetworkConfig::default`）。`default_for(packaged)`（config.rs:1008〜）も `Self::default()` を基点にするため空を継承。
- **RFC1918/非ルータブル走査の単体テストを追加済み**:
  - `config.rs:2068-2092` `default_bootstrap_reachability_tests::the_default_bootstrap_list_has_no_private_range_address`
    - `default()` と `default_for(true)` / `default_for(false)` の `bootstrap_peers` を走査し、非ルータブル IPv4（10.0.0.0/8・172.16.0.0/12・192.168.0.0/16、加えて loopback・link-local・CGNAT 100.64/10・0.0.0.0）を含まないことを assert。
  - 補助: `the_classifier_flags_the_known_private_ranges`（config.rs:2095）, `the_classifier_allows_public_and_hostname_addresses`（config.rs:2109）。
  - 分類器本体: `multiaddr_has_nonroutable_ipv4`（config.rs:2013）, `ipv4_is_nonroutable`（config.rs:2030）。
- config.rs 全体に `172.`/`10.`/`192.168` のアドレスリテラルは本番既定に無し（テスト入力の 2097 行 `172.24.51.174` 等を除く）。

→ 要件（既定から 172.x を除去＝空、RFC1918 走査テスト追加）はコード上すべて充足済み。

## cargo test の実 pass/fail 件数: **未取得（環境ビルドブロッカー）**

`cargo test -p miasma-core --locked --lib config`（共有 CARGO_TARGET_DIR=C:/work/miasma-beta12-src/target、vcvars64 有効化）を複数回実行したが、依存クレート `audiopus_sys v0.2.2` のビルドスクリプトが失敗し、crate 全体がコンパイルできずテストに到達できない。

エラー要旨（ジョブ 1ad5b8d93d のログ）:
```
CMake Error at CMakeLists.txt:7 (project):
  Generator "Visual Studio 17 2022" could not find any instance of Visual Studio.
```
- `audiopus_sys` が CMake + "Visual Studio 17 2022" ジェネレータで Opus をビルドしようとするが、本環境は VS BuildTools のみで完全な VS インスタンスが無いため CMake がジェネレータを検出できず exit 101。
- これは config モジュールとは無関係の依存（音声 FFI）で発生する**環境起因のビルドブロッカー**。担当 1/5 の config.rs 編集では解決不可。回避には CMake ジェネレータを Ninja に切替（`CMAKE_GENERATOR=Ninja`）等の共有ビルド環境の修正が必要で、本担当範囲外かつ他会話のビルドに影響する。

## 取得件数の明記
- 確認した実装箇所: 既定 bootstrap 1件（config.rs:1000）、RFC1918 走査テスト 1件（config.rs:2077）、補助分類器テスト 2件（2095・2109）、分類器本体 2関数（2013・2030）。
- 実行した cargo test の pass/fail 実件数: **0件取得**（audiopus_sys の CMake/VS 検出失敗によりコンパイル未到達）。

## 結論
コードは担当要件を充足済み。ただし必須出力である「cargo test の実 pass/fail 件数」は、環境側のビルドブロッカー（audiopus_sys の CMake が VS BuildTools をインスタンスとして認識できない）により取得できず。

---

# 担当 2/5 結果: ホルダー探索・預け入れを iroh 経由にする

worktree: C:/Users/M118A8586/AppData/Local/Temp/m365-companion/agents/offC (branch offline/C)

## 既に origin/main で満たされていた部分（コードを読んで確認）
- **預け入れ・回収は既に iroh（n0 relay/discovery）経由**: `chat/mailbox/transport.rs:52-55` が `node.connect_alpn(&holder, CHAT_ALPN)` を使い、`transport/iroh_direct.rs:662-671` の `connect_alpn` が iroh エンドポイントで relay hint 付き dial する。n0 discovery/relay は既定 on（`config.rs:782-798,872-874`）。libp2p/DHT 経由ではない。
- **`custody_copies` 部数確保**: `chat/mailbox/client.rs:93-98`（`copies.clamp(1,8)`）、`client.rs:170-172`（`rep.held_by.len() >= self.copies` で停止）、`chat/service.rs:1048-1051`（`MailboxClient::new(.., self.settings.custody_copies)`）。
- **ホルダー候補選定**: `chat/service.rs:1019-1026` `holders_for` が宛先以外の到達連絡先を返し、`client.rs:166-178` の `deposit` が到達不能ホルダーを `failed` に積んで到達可能ホルダーに copies 件確保。到達可能性は iroh dial 成否で動的判定。
- **オフライン受領の単体テスト（既存）**: `chat/mailbox/sim_tests.rs:174-222`（送信者預け入れ→受信者オフライン→後接続受領）、2ホルダー版 `250-268`、到達不能ホルダー skip `271-317`。これらが依頼のインプロセス・マルチノード型パターン。

## 今回の変更（file:line）
未達だったのは PART C 中核要件「預け入れ失敗を『not delivered』として報告し、success にしない」。以下を局所改修（holder 選定/預け入れ近傍のみ、PART A と非衝突）。

1. `crates/miasma-core/src/chat/service.rs:1037-1061` — `deposit_with_holders` の戻り値を `()` から `bool` に変更。到達可能ホルダーが1つ以上受領したときのみ `true`。custody off・ホルダー無し・全員到達不能/拒否は `false`。doc コメントも更新。
2. `crates/miasma-core/src/chat/service.rs:700-721` — 呼び出し元で戻り値を受け、`false`（どのホルダーも受領せず）のとき outbox の `last_error` を `"not delivered: no holder took a copy"` に設定。`spawn_blocking(...).await.unwrap_or(false)` で JoinError も安全側（未配送）に倒す。これにより status が「ホルダーに安全に預かられている」と誤表示しない。
3. `crates/miasma-core/src/chat/mailbox/sim_tests.rs` 末尾に単体テスト2件追加:
   - `a_deposit_with_the_only_holder_offline_takes_no_copy` — 唯一のホルダーがオフライン時に `held_by` 空（`n==0`）、後で受信者が接続しても取得ゼロ、送信者側に outbox が残ることを検証。
   - `a_deposit_only_to_an_untrusting_holder_takes_no_copy` — ホルダーが送信者を信頼せず拒否時に `held_by` 空、受領ゼロを検証。

セキュリティ要件は不変更（PQ/E2EE/認証に手を加えず、ホルダーは暗号文のみ。既存挙動を維持）。

## 改行コードについて（新会話で再検証）
`git diff origin/main --numstat`（raw）と `--ignore-all-space --numstat` が **両方とも service.rs=88/9・sim_tests.rs=181/0 で完全一致**。すなわち改行コードによる偽差分（whole-file rewrite）は無く、実内容の変更のみ。sim_tests.rs は追加のみ（削除 0＝既存テスト保持、うち本担当の追加は上記2件、残りは別サブ担当の directed invite テスト群）。

## cargo test の実 pass/fail 件数: **0件取得（rustc 不在によりコンパイル一切不可）— 新会話で再検証**
当初は `audiopus_sys` の CMake/VS 検出失敗が原因と記録したが、新会話で実測したところ、その手前で **rustc（ツールチェーン本体）が存在しない**ことが真の原因と確定した。実証:
- `cargo --version` → `cargo 1.99.1` は動く。しかし `rustc --version` → `error: missing manifest in toolchain 'stable-x86_64-pc-windows-msvc'`。
- `C:\Users\M118A8586\.rustup\toolchains` は**空ディレクトリ**（toolchain 本体が未配置）。
- `rustup which rustc` は再 DL を試みるが `error: failed to install component: 'cargo-x86_64-pc-windows-msvc', detected conflict: 'bin\cargo.exe'` で失敗（別途インストール済みの cargo.exe と衝突し修復不可）。
- `cargo test -p miasma-core --locked --lib chat::mailbox:: --no-run`（共有 `CARGO_TARGET_DIR=C:/work/miasma-beta12-src/target`）を実行 → ログ末尾は `error: missing manifest in toolchain` のみ。audiopus_sys の CMake 段階にすら到達せず、**コンパイル自体が開始できない**。

したがって追加した sim_tests 2件の実 pass 件数は **0件取得（ビルド不能）**。これは PART C のコード範囲外の環境破損であり、rustup 修復はツールチェーン全体を触り隔離契約に反するため本担当では修復しない。変更の整合はコード目視でのみ確認。

## コミット/PR について（新会話で再検証）
本担当2/5の変更は**既にコミット済み**。`git log` 上、HEAD=`d3e4d31`（origin/main=`c793a90` より先行）。service.rs の `deposit_with_holders -> bool` 化・呼び出し元の not-delivered 記録・sim_tests 2件は、`git diff origin/main` に service.rs 88/9・sim_tests.rs 181/0 として確定反映済み（grep で service.rs:705,718,1037、sim_tests.rs:446,472 を実在確認）。CI 配線も `.github/workflows/ci.yml:76-77` が `cargo test -p miasma-core --lib -- chat::mailbox::` を実行し、追加テストは `chat::mailbox` 配下のため収集される。現時点の未コミット差分は追跡ファイルでは `result_C.md` のみ（`git status` 実測）。push/PR は PART C 全体サマリの管掌。

## 取得件数の明記
- 変更したコード箇所: service.rs 2箇所（`deposit_with_holders` の bool 化、呼び出し元の未配送記録）、sim_tests.rs 1箇所（テスト2件追加）。
- 追加した単体テスト: 2件（オフライン・ホルダー不在時の未配送を証明）。既存のオフライン受領テスト（iroh/custody_copies 挙動を網羅）は origin/main に 5件以上あり保持。
- 実行した cargo test の pass/fail 実件数: 0件（ビルド未到達）。

---

# PART C 最終サマリ（全5項目の到達状況・コミット一覧）

worktree: C:/Users/M118A8586/AppData/Local/Temp/m365-companion/agents/offC (branch offline/C)

2/5 セクション時点では「共有未コミットが混在するためコミットしない」と記録したが、その後、各担当の変更を**変更ファイルだけを明示 add** して個別コミットに分離済み（他担当の未コミット作業やゴミファイルは巻き込まない）。origin/main..HEAD のコミット一覧:

| commit | 内容 | 項目 |
|---|---|---|
| c0e7547 | 既定 config からプライベート bootstrap 除去＋network publish が remote copy を要求 | (1)(5) |
| 267a16f | network publish 既定が zero-remote-copy を拒否するテスト | (5) |
| 24ee2f0 | direct receive fixture / 整形修正 | - |
| 31c6f68 | `miasma offline-check` 自己診断コマンド（WIP、13 単体テスト） | (4) |
| 92c8c8f | origin/main を merge | - |
| e42cd14 | daemon: raw-data publish パスで >=1 remote shard ACK を強制 | (5) |
| fb6425d | `PublishOptions::accepts` ヘルパー＋remote-copy ポリシー単体テスト | (5) |
| 0054c9e | CI: miasma-cli の lib テストを実行（offline-check を CI 配線） | (4) |
| d3e4d31 | directed-share invite をホルダーに預けてオフライン配信（本機能の中核） | (3) |
| bd83a3c | CI: chat::mailbox custody 単体テストを --lib で実行（CI 配線） | (3)(2) |

## 項目別の到達状況

- **(1) 既定からプライベート bootstrap 除去＋RFC1918 走査テスト**: 完了（c0e7547、config.rs の既定空＋分類器テスト）。
- **(2) ホルダー預け入れ・回収を iroh 経由＋預け入れ失敗を not-delivered 報告**: 完了（既存 iroh 経路を確認、service.rs の `deposit_with_holders -> bool` 化で未配送を正直報告、sim_tests 2件）。
- **(3) directed-share invite のオフライン配信（mailbox 預け）**: 完了（d3e4d31）。
  - 新タグ `for_directed_recipient`（private/group と分離）＋`item_id_for_directed`（ids.rs）。
  - `deposit_directed`/`collect_directed`（client.rs）、`deposit_directed_invite`/`collect_directed_invites`（service.rs）。
  - daemon: `process_directed_send` が直接送信を best-effort 化し、**mailbox 預けの成否を「sent」の定義**に変更。holder が1つも取らなければ `Err` を返し、送信者に成功 id を渡さない。受信者は `DirectedInbox` list 時に holder から回収し inbox 保存＋ACK（holder はコピー削除）。
  - テスト: ids 単体2件（タグ安定/分離、item id）＋sim_tests 5件（オフライン往復、ACK 後削除、offline/untrusting holder で未配送、private/directed 経路分離）。
- **(4) `miasma offline-check` 自己診断コマンド**: 完了（31c6f68 実装＋0054c9e で CI 配線）。verdict ロジックの 13 単体テストを CI の Windows ジョブ（CLI が既にビルドされる場所）で `cargo test -p miasma-cli --lib` により実行。
- **(5) network publish が既定で >=1 remote copy を要求**: 完了（c0e7547/267a16f/e42cd14/fb6425d）。既定で zero-remote-copy publish を拒否、raw-data パスで remote shard ACK を強制、`PublishOptions::accepts` ヘルパーと単体テスト。

## CI 配線（契約4「緑に見えて走らない」の回避）
- `chat::mailbox::` の custody 単体テスト（sim_tests 7件＋ids 2件）は `#[cfg(test)]` のため `--lib` でしか走らず、既存 CI の `--tests` や `secure_file::/root_key::` フィルタでは拾われなかった。test-core（Ubuntu）に `cargo test -p miasma-core --lib --locked -- chat::mailbox::` を追加（bd83a3c）。
- offline-check の CLI lib テストは Windows ジョブに `cargo test -p miasma-cli --locked --lib` を追加（0054c9e）。
- いずれも純ロジック/シミュレータで platform-neutral（ネットワーク・feature flag 不要）。
- ci.yml は origin/main 由来の CRLF 7対を保持したまま、LF 領域には LF で挿入（行末汚染なし）。

## 改行コードの衛生
- 編集途中で client.rs / ids.rs / daemon/mod.rs がファイル全体 CRLF 化していたため、HEAD（LF）へ正規化してからコミット。コミット済み差分は全ファイル LF、純増中心（directed invite 一式 +457/-16）。

## cargo test の実 pass/fail 件数: **未取得（環境ビルドブロッカー）**
- 依存 `audiopus_sys v0.2.2` の CMake が "Visual Studio 17 2022" ジェネレータを検出できず（本環境は VS BuildTools のみ）、miasma-core のコンパイルがテストに到達しない。加えて rustfmt のツールチェーン manifest 破損で整形チェック不可。
- このため全テスト（既存＋今回追加）の**実 pass/fail 件数は 0件取得**。整合はコードレビューでのみ確認（API・型・フィールド名・変数スコープを grep で突き合わせ）。CI（Ubuntu/Windows の正規トゥールチェーン）では上記配線により実行される見込み。

## 未追跡の作業用ファイルについて
- 作業ツリーに残るログ（`*.log`）、ハーネス（`cfg_harness.*`）、ラッパ（`run_*.cmd`/`*.bat`）、設計メモ（`.fleet_scratch_C_invite_design.md`）、awk 事故産物（`2000`）はいずれも**未追跡のゴミで、どのコミットにも含めていない**。push 対象は追跡ファイルのみ。

---

# 担当 4/5 結果（再検証・確定）: network-publish 既定で遠隔 ACK 1件以上を必須化

worktree: C:/Users/M118A8586/AppData/Local/Temp/m365-companion/agents/offC (branch offline/C)
担当範囲: report (d) / ブリーフ PART C 項目3 ＝「既定 `PublishOptions`（遠隔確認数0許容, coordinator.rs:135-163）を、既定で最低1件の異なる遠隔ホルダー ACK を『done』条件とするよう変更。得られなければ『このデバイスにのみ保存』と表示。strict モードは従来どおり。既定で遠隔 ACK なしが成功と報告されないことを証明するテストを追加。」

## 実装（コミット済み、origin/main..HEAD の実差分を確認）
差分: `coordinator.rs +79/-0`、`daemon/mod.rs +257/-31`(本項目分を含む)。関連コミット: c0e7547 / e42cd14 / 2db575a / fb6425d。

### coordinator.rs
- `coordinator.rs:138` `struct PublishOptions` に `min_remote_distinct_shards: usize`（:151）。
- `coordinator.rs:163` `default()` は `min_remote_distinct_shards = 0`（＝レガシー best-effort、後方互換で温存）。
- `coordinator.rs:177` **`network_default()` を新設 → `min_remote_distinct_shards = 1`**（デーモン既定）。
- `coordinator.rs:191` **`accepts(remote_distinct) -> Result<(),(usize,usize)>`**: 観測遠隔数が閾値未満なら `Err((need, got))`。
- `coordinator.rs:886` 配布経路で `remote_distinct < options.min_remote_distinct_shards` のとき `InsufficientShares { need, got }` を返す。
- strict は従来通り: `strict(params)` は `min = data_shards`（coordinator.rs:163 近傍の strict コンストラクタ）。

### daemon/mod.rs
- `daemon/mod.rs:1315,1348,1382` raw/ファイル/保護付きファイルの各 publish 経路が **`PublishOptions::network_default()`**（既定 min=1）を使用。
- `daemon/mod.rs:2359-2374` `publish_error_text()`: `InsufficientShares { got: 0, .. }` を **「stored only on this device: no remote holder acknowledged a copy …」** に変換。`{ need, got }` 一般形も人間可読文に。
- `daemon/mod.rs:2809-2816` publish 実経路でポリシー判定し、未達なら `Err(InsufficientShares{need,got})` を返して DhtRecord を公開しない（＝成功 id を返さない）。

## 追加テスト（本担当分 合計 6件 — 静的に全確認）
### coordinator.rs `mod publish_options_accepts_tests`（coordinator.rs:2623〜, 4件）
1. `default_accepts_zero_remote_copies` — レガシー既定(min=0)は `accepts(0)`/`accepts(5)` とも Ok。
2. **`network_default_refuses_zero_remote_copies`** — 既定(min=1)は `accepts(0) == Err((1,0))`。★「遠隔ACKなし＝成功ではない」の証明。
3. `network_default_accepts_one_or_more_remote_copies` — `accepts(1)`/`accepts(10)` とも Ok。
4. **`strict_requires_data_shards_distinct_remote_copies`** — strict(data_shards=10) は `accepts(9)==Err((10,9))`、`accepts(10/11)` Ok。★strict 従来動作の維持を証明。

### daemon/mod.rs `mod publish_content_remote_ack_tests`（daemon/mod.rs:3174〜, 2件, in-process 実ノード `#[tokio::test(multi_thread)]`）
5. **`raw_publish_default_requires_a_remote_ack_and_reports_failure_when_offline`** — ピア0の実ノードで raw publish を `network_default()` で実行→ `InsufficientShares{need:1,got:0}` で失敗することを assert（成功 mid を返さない）。さらに `publish_error_text` が「stored only on this device」を含むことを確認。★中核要件の end-to-end 証明。
6. `raw_publish_legacy_default_still_succeeds_offline` — 同条件でも `PublishOptions::default()`(min=0) なら `Ok`（後方互換の保証）。

## cargo test の実 pass/fail 件数: **0件取得（環境の Rust 標準ライブラリ破損によりコンパイル不能）**
この会話で再実測した確定事実:
- ツールチェーン本体の `rustc.exe -vV` は動作（rustc 1.99.1）。しかし **標準ライブラリの配布物が物理的に欠落**している:
  - `…\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib` に `libstd-*` / `libtest-*` / `libcore-*` の rlib が **1つも存在しない**。
  - rustup の `…\lib\rustlib\components` ファイルが **消失**（「指定されたパスが見つかりません」）。
- この状態で `cargo test`（共有 `CARGO_TARGET_DIR=C:/work/miasma-beta12-src/target`, vcvars64 有効, PATH から mingw 除去, rustup シムをバイパスした直接 cargo 呼び出し）を実行したが、実クレート(ring, x509-parser 等)が **`E0463: can't find crate for std`** で失敗し、テストに到達できない。
- 以前の試行で判明していた `audiopus_sys`(CMake/VS 検出失敗) は `--no-default-features --features iroh` で回避済みだが、その手前の **std 欠落が上位ブロッカー**。
- 修復には `rustup target add x86_64-pc-windows-msvc`（rust-std 再取得）が必須。しかしこれは (a) オフライン環境で取得不可の可能性が高く、(b) 共有 Rust インストールへの破壊的変更で並行する他会話(A/B/D/E)のビルドを壊し、エージェント契約「自分の作業完了まで他走行から見える状態を変えない」に反するため、**本担当では実行しない**。

## 取得件数の明記
- 変更/確認したコード箇所: coordinator.rs 2関数新設(`network_default`, `accepts`)＋フィールド1＋配布経路の判定1、daemon/mod.rs 3経路の既定差し替え＋エラー文言変換＋publish 実経路のポリシー強制。
- 追加した単体/統合テスト: **6件**（coordinator 4件、daemon 2件。うち in-process 実ノード 2件）。
- 実行した cargo test の実 pass/fail 件数: **0件取得**（環境の rust-std 物理欠落によりコンパイル未到達。コードは静的レビューでのみ整合確認）。

## 結論
担当範囲（network-publish 既定で遠隔 ACK ≥1 を必須化、strict 維持、遠隔ACKなしを成功としない証明テスト追加）の **コードとテストは実装・コミット済み**。唯一の未達は必須出力「cargo test の実 pass/fail 件数」で、これは担当コード範囲外の**マシン側 Rust 標準ライブラリ破損（+オフラインで修復不可）**という環境ブロッカーによる。正規トゥールチェーンの CI 環境では本テスト群が実行される見込み。
