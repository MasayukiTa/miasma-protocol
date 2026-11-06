# result_A（offline/A）

状態: PR #261 に反映済み。コミット b4ff438 を origin/offline/A に push 済み。

## 変更点
- config.rs: [chat] に上限の設定キーを3つ追加。custody_max_total_bytes 既定2MiB、custody_max_items 既定256、custody_ttl_days 既定14。serde default 付きで旧 config.toml と後方互換。ChatConfig::default にも反映。
- holder.rs: CustodyLimits::from_config が上記3キーを読み clamped でハード上限 4MiB/1024件/30日 に丸める。従来 enabled のみ設定で上限は default のハードコードだった点を解消。

## テスト
- 追加: holder.rs custody_tests に limits_come_from_config_and_are_clamped 1件。設定値の伝播と、上限超過時に clamped でハード上限へ丸められることを検証。
- 既存: custody_tests 群 disk_tests survives_a_restart/a_wrong_key_starts_empty/a_tightened_ceiling_drops_items_on_restore 他、sim_tests、tests/chat_custody_net_test.rs 2ノード往復。

## 残課題
- ビルド/テスト未実行: C: ドライブ空き0のため cargo 実行不可。検証はCIに委譲。
- docs/TROUBLESHOOTING.md 未更新: nothing is written to disk の記述が今回の DiskCustody 封印ディスク保存と矛盾。全体書き戻しは空き0で途中失敗時に追跡ファイル破損の恐れがあり安全に実施不可のため見送り。新上限キーの追記も同様。
- Gap1 未実装の理由: 相手がオフラインの時は信頼する保持者へ封印複製を預け、待機中として表示する既存経路に限定した。相手自身への直接預託経路は、相手の受信鍵での封印確認とリプレイ防止の設計が未確定で、誤って平文や無確認で預けると情報漏えい/二重適用の恐れがあり安全に実装できないため今回は見送った。
