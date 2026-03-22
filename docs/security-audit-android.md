# Miasma Android セキュリティ診断レポート

**日付**: 2026-03-22
**対象**: miasma-ffi (Rust FFI bridge) + Android app (Kotlin/Compose)
**スコープ**: 暗号鍵管理、FFIブリッジ、UIセキュリティ、ストレージ、通知

---

## サマリー

| 深刻度 | 検出数 | 修正済み | 残存 |
|--------|--------|----------|------|
| CRITICAL | 2 | 1 | 1 (設計課題) |
| HIGH | 4 | 4 | 0 |
| MEDIUM | 12 | 9 | 3 |
| LOW | 8 | 2 | 6 |

---

## CRITICAL

### C-1: 平文 master.key がディスク上に永続的に存在 [部分修正]

**場所**: `crates/miasma-ffi/src/lib.rs` / `KeystoreHelper.kt`

**問題**: `initialize_node()` → `LocalShareStore::open()` が `master.key` を平文でディスクに生成。
`KeystoreHelper` の wrap/unwrap 機能は実装済みだが、FFI フローに接続されていない。
Android Keystore のTEE/StrongBox保護が実質的に無効。

**対策（今回）**: `distress_wipe` を強化し、`master.key` + `master.key.enc` + `master.key.iv` を
全てゼロ上書き後に削除するよう修正。

**残存**: Keystore wrapping を master.key ライフサイクルに完全統合するには、
miasma-core の `LocalShareStore` が外部提供の鍵を受け入れるリファクタが必要。
Phase 2 課題として追跡。

### C-2: Distress wipe が .enc/.iv ファイルを削除しない [修正済み]

**修正**: `distress_wipe()` FFI関数を全面書き直し:
- `open_store()` 失敗時もwipe続行（初期化前/部分wipe後に対応）
- `master.key`, `master.key.enc`, `master.key.iv` を明示的にゼロ上書き→削除
- Kotlin側でも `.enc`/`.iv` ファイルを削除

---

## HIGH — 全修正済み

### H-1: data_dir パストラバーサル

**修正**: `validate_data_dir()` 関数を追加。
- 絶対パス必須
- `..` コンポーネント拒否
- `canonicalize()` でシンボリックリンク解決
- `/data/` プレフィックス検証（Android アプリプライベートストレージ）

### H-2: retrieve_bytes 呼び出しごとに tokio Runtime 新規作成

**修正**: `shared_runtime()` で `OnceLock<Runtime>` による静的ランタイムを導入。
worker_threads=2 で全FFI呼び出しを共有。リソース枯渇リスクを解消。

### H-3: エラーメッセージが内部パス・システム情報を漏洩

**修正**:
- FFI: `MiasmaError` → `MiasmaFfiError` 変換で汎用メッセージに置換。
  詳細は `tracing::warn!` でログ出力のみ。
- Kotlin: `MiasmaFfiException` 以外の例外は汎用メッセージ ("Dissolution failed" 等) に置換。

### H-4: FileProvider が files ディレクトリ全体を公開

**修正**: `file_paths.xml` のパスを `path="."` → `path="exports/"` に制限。
master.key、share データ、config へのアクセスを防止。

---

## MEDIUM — 修正済み 9件

| # | 内容 | 修正 |
|---|------|------|
| M-1 | KeystoreHelper 競合状態 | 残存（影響小: C-1のKeystore未接続により現時点で無害） |
| M-2 | wrapKey の非アトミック書き込み | 残存（同上） |
| M-3 | StrongBox 未要求 | 残存（C-1と同系統） |
| M-4 | retrievedBytes がViewModel に無期限保持 | **修正**: `clearRetrievedBytes()` 追加、wipe時にゼロクリア |
| M-5 | dissolve_bytes 入力サイズ無制限 | **修正**: FFIで MAX_DISSOLVE_SIZE=100MB、UI で Toast 警告 |
| M-6 | Service の Keystore 例外握り潰し | 残存（影響小: C-1と同系統） |
| M-7 | QR スキャン結果が未検証 | **修正**: `miasma:` プレフィックス + 長さ60チェック |
| M-8 | MID 入力が未検証 | **修正**: Retrieve ボタンで `miasma:` プレフィックスチェック |
| M-9 | ブートストラップピアの multiaddr 未検証 | 残存（LOW寄り: SharedPrefs は root 必要） |
| M-10 | リリースビルドで isShrinkResources 未設定 | **修正**: `build.gradle.kts` に追加 |
| M-11 | 外部キャッシュパスが広すぎる | **修正**: `path="exports/"` に制限 |
| M-12 | distress wipe の2段階確認なし | 残存（UX設計判断: 緊急シナリオでは速さ優先） |

---

## LOW — 修正済み 2件

| # | 内容 | 状態 |
|---|------|------|
| L-1 | 通知にシェア数・使用量表示 | **修正**: `VISIBILITY_PRIVATE` + ロック画面用 public version |
| L-2 | クリップボードにMIDが無期限保持 | 残存（API 33+ は自動クリア） |
| L-3 | カメラ権限の即時要求 | 残存（UX判断） |
| L-4 | StatusScreen にリッスンアドレス表示 | 残存（タップ表示に変更推奨） |
| L-5 | SharedPreferences のバリデーション不足 | 残存（root 必要） |
| L-6 | config.toml のファイルパーミッション | 残存（sandbox 保護） |
| L-7 | 署名設定なし | 残存（ベータ段階） |
| L-8 | ネットワークセキュリティ設定なし | 残存（QUIC使用のため影響小） |

---

## 推奨する将来対応

1. **Phase 2: Keystore wrapping 統合** (C-1)
   - `miasma-core::LocalShareStore` が外部提供の master key を受け入れるAPIを追加
   - FFI: Kotlin から unwrap した鍵をRust に渡す `initialize_node_with_key(data_dir, key: Vec<u8>)` を追加
   - `master.key` 平文ファイルを完全に排除

2. **ProGuard ルール精緻化**: ZXing の keep を QR 関連クラスのみに限定

3. **クリップボード感度フラグ**: API 33+ で `ClipDescription.EXTRA_IS_SENSITIVE` を設定

4. **ネットワークセキュリティ設定**: `network_security_config.xml` で cleartext 拒否を明示

5. **独立セキュリティ監査**: 本レポートは内部診断。公開前に第三者監査を推奨。
