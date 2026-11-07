# result_C — network-publish の既定を遠隔 ACK 1件以上必須にする（担当範囲 4/5）

branch: `offline/C`
worktree: `C:/Users/M118A8586/AppData/Local/Temp/m365-companion/agents/offC`
PR: #262（OPEN）

## 担当範囲（4/5）

`coordinator.rs:135-163` の既定 `PublishOptions`（遠隔確認数 0 許容）を、既定で少なくとも 1 件の異なる遠隔ホルダー ACK を「done」の条件とするよう変更。得られない場合は「このデバイスにのみ保存」と表示。strict モードは従来どおり。既定で遠隔 ACK なしが成功と報告されないことを証明するテストを追加。

## レビュー指摘への対応（本ターンの主修正）

レビュアー指摘は**妥当**だった: 当初の修正は**ファイル publish 経路のみ**を `network_default()` に配線しており、`daemon/mod.rs` の `publish_content` を通る
**生データ publish 経路（`ControlRequest::Publish`）** と **directed 経路（`process_directed_send`）** が enforcement を一切通らず、遠隔 ACK 0 件でも `publish_record` で DhtRecord を公開し成功を返していた。要件「既定で遠隔 ACK なしが成功と報告されない」が生データ経路で未達だった。

### 修正内容

1. **`publish_content`（daemon/mod.rs:2721-）を enforcement 経路に変更**
   - シグネチャに `options: crate::network::PublishOptions` を追加。
   - 本体を、自前の「shares を put して自分だけをホルダーにした locations を組み無条件 publish」から、
     `coord.store_locally_and_distribute(shares, params)`（ファイル経路と同じ、実際に遠隔配布を試み `remote_distinct` を数える関数）呼び出しに置換。
   - `if let Err((need, got)) = options.accepts(remote_distinct) { return Err(MiasmaError::InsufficientShares { need, got }); }` を DhtRecord 公開の**前**に挿入。0 件 ACK は公開も成功報告もしない。
2. **呼び出し元の配線**
   - `ControlRequest::Publish`（生データ＝本担当, daemon:1308-1316）→ `PublishOptions::network_default()`（min=1）。
     さらにエラー整形をファイル経路と同じ `ControlResponse::Error(publish_error_text(e))` に統一（従来 `e.to_string()` で「このデバイスにのみ保存」文言を通していなかったのを修正）。
   - `process_directed_send`（範囲 c = 別会話担当, daemon:2416 付近）→ 挙動を変えないため `PublishOptions::default()`（min=0, レガシ best-effort）を明示。directed の「送信完了」判定（invite deposit ACK）は範囲 c の領域なので一切触っていない。

### 変更 file:line

- `crates/miasma-core/src/daemon/mod.rs:2721-2729` — `publish_content` シグネチャに `options` 追加（`_store`/`_listen_addrs` は配布を coord に委ねたため未使用化、`_` で明示）。
- `daemon/mod.rs:2741-2753` — `store_locally_and_distribute` 呼び出し＋`options.accepts(remote_distinct)` enforcement（0 件→`InsufficientShares`）。
- `daemon/mod.rs:1308-1321` — 生データ経路に `network_default()` を配線し、エラーを `publish_error_text(e)` で整形。
- `daemon/mod.rs:2416 付近` — directed 経路に `PublishOptions::default()` を明示（挙動不変・範囲 c 非干渉）。

### 既存（前ターンで完了済み・不変）

- `coordinator.rs:167-181` `PublishOptions::network_default()`（min=1）
- `coordinator.rs:183-197` `accepts()`（pub(crate)、done の単一定義）
- `coordinator.rs:161-165` `strict()`（未変更）
- `coordinator.rs:886-888` `dissolve_and_publish_with_options` の enforcement
- `daemon/mod.rs:1342,1379` ファイル経路 publish は既に `network_default()`
- `daemon/mod.rs:2361` `publish_error_text(e: MiasmaError)`（値渡し）→ InsufficientShares{got:0} を「stored only on this device（このデバイスにのみ保存）」と表示

## テスト

### 追加（本番コード）

- `crates/miasma-core/src/network/coordinator.rs:2620-2699` `publish_remote_ack_default_tests`（6 件、既存）。
- `crates/miasma-core/src/daemon/mod.rs` 末尾 `publish_content_remote_ack_tests`（**新規 2 件**、実ノード）:
  1. `raw_publish_default_requires_a_remote_ack_and_reports_failure_when_offline` — 単一ノード（peer なし）で `publish_content(.., network_default())` を呼ぶと `InsufficientShares{need:1,got:0}` を返す（成功にならない）。加えて `publish_error_text` が「stored only on this device」を返すことも確認。
  2. `raw_publish_legacy_default_still_succeeds_offline` — 同条件で `PublishOptions::default()` なら `Ok`（後方互換）。
  既存の単一ノードハーネス（`large_file_stream_integrity_tests` の `MiasmaCoordinator::start` + `collect_listen_addrs`）と同型。

### 実行結果（環境制約と検証方法）

ワークスペースの `cargo test` は**この環境では実行不可**: MSVC の `cl.exe` が無く、C 依存 crate（aws-lc-rs 等）のビルドが `error occurred in cc-rs: failed to find tool "cl.exe"` で失敗する（offline/A が記録済みの既知インフラ制約）。gnu ツールチェインは std target 未導入。

そのため、`publish_content` に挿入した enforcement 分岐を**逐語で**切り出した自己完結ハーネス `ackdef_selftest.rs` に、生データ経路を表すテストを追加し gnu rustc で実行:

```
running 9 tests
test publish_content_raw_path_tests::raw_publish_offline_under_legacy_default_still_ok ... ok
test publish_content_raw_path_tests::raw_publish_offline_under_default_is_insufficient_shares_not_success ... ok
test publish_content_raw_path_tests::raw_publish_with_one_remote_ack_under_default_ok ... ok
test publish_remote_ack_default_tests::network_default_requires_one_remote_ack ... ok
test publish_remote_ack_default_tests::network_default_rejects_zero_remote_acks ... ok
test publish_remote_ack_default_tests::network_default_accepts_one_or_more_remote_acks ... ok
test publish_remote_ack_default_tests::zero_remote_ack_maps_to_insufficient_shares_not_success ... ok
test publish_remote_ack_default_tests::explicit_default_still_allows_zero_remote_acks ... ok
test publish_remote_ack_default_tests::strict_still_requires_data_shards_remote_acks ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`publish_content_enforcement` は本番 `publish_content` の `if let Err((need,got)) = options.accepts(remote_distinct) { return Err(InsufficientShares) }` と同一。型・可視性（`accepts`/`store_locally_and_distribute` ともに `pub(crate)`、daemon は同一 crate）、`publish_error_text(e)` の値渡しをソース上で確認済み。

## 静的に確認した整合

- `store_locally_and_distribute` 戻り `(Vec<ShardLocation>, usize)` と `DhtRecord.locations: Vec<ShardLocation>` 整合。
- `accepts` / `store_locally_and_distribute` は `pub(crate)`、daemon から呼べる。
- `publish_error_text(e: MiasmaError)` は値渡し。呼び出しを 2 箇所とも値に統一（当初 `&e` で書いた型不一致を修正済み）。

## まだ不足していること（正直な限界）

- MSVC cl.exe 不在によりワークスペース全体の `cargo test -p miasma-core --lib`（新規実ノードテスト 2 件を含む）は本環境で未実行。ロジック同値性は gnu rustc ハーネスで実証済みだが、実ノードテストの緑は cl.exe が入った CI/環境での最終確認が必要。
- directed 経路（範囲 c）は意図的に `default()` 据え置き。directed の「送信完了」の遠隔保管要件を課すかは範囲 c の判断。
- 作業ツリーは別会話由来の CRLF 化・一部重複行の表示揺れがあるが、本修正の対象行ではなく add していない。
