# 未完タスク一覧 (優先度順)

**作成日**: 2026-04-01
**最終更新**: 2026-04-01
**基準バージョン**: 0.3.1-beta.1
**テスト**: 776 (全通過、失敗0、ignored 10)

---

## 優先度の考え方

- **P0 (Critical)**: これがないとベータとして外部に出せない
- **P1 (High)**: 公開ベータ前に必要
- **P2 (Medium)**: プロダクションリリース前に必要
- **P3 (Low)**: プロダクション品質向上のため望ましい
- **P4 (Deferred)**: 明示的にスコープ外 or 長期ロードマップ

---

## P0 — Critical (外部ベータ阻害)

### P0-1: コード署名証明書の取得と適用

- **種別**: リリース/インフラ
- **現状**: パイプライン検証済 (2026-04-01)
  - `signtool.exe` 確認済 (Windows Kits 10.0.26100.0)
  - `sign-release.ps1` 完成 — 3ステージ (Authenticode + SHA256 + GPG)
  - `build-release.ps1`, `package-release.ps1` 完成
  - **唯一のブロッカー: コード署名証明書の購入**
- **必要なもの**: EV コード署名証明書 (Sectigo, DigiCert 等)
- **残作業**:
  - 証明書購入・申請
  - `.\scripts\sign-release.ps1 -CertThumbprint "XXXXX"` で署名
  - CI に署名ステップ追加
- **工数**: 1-2日 (証明書入手後)
- **ブロッカー**: 証明書取得プロセス (EV は審査あり、1-2週間)

### P0-2: Windows クロスデバイス検証 (Stage 1-3)

- **種別**: 検証
- **現状**: 同一マシン2デーモン検証 **完了** (2026-04-01)
  - ピア接続: PASS (bootstrap + mDNS 発見)
  - A→B network-publish + B retrieves: PASS (tiny + 4K, MD5一致)
  - B→A network-publish + A retrieves: PASS (MD5一致)
  - Directed sharing A→B: PASS (send→inbox→challenge→confirm→retrieve→revoke 全ステップ)
  - Directed sharing B→A: PASS (逆方向も全ステップ成功)
- **残作業**:
  - Stage 1: 物理2台目マシンでの mDNS 発見検証 (プロトコルは上記で実証済)
  - Stage 2: VPN/ファイアウォール越え
  - Stage 3: hostile network
- **工数**: 1-2日 (2台目マシンへのアクセス後)
- **ブロッカー**: 2台目マシンへのアクセス

### P0-3: Android 実機ビルド・起動検証

- **種別**: モバイル/検証
- **現状**: ビルド環境検証済 (2026-04-01)
  - `cargo-ndk 4.1.2`: インストール済
  - `aarch64-linux-android` Rust ターゲット: インストール済
  - Android NDK: **未インストール** — これが唯一のビルドブロッカー
  - Android SDK: 未インストール
  - Java: 1.8 (17必要)
  - Gradle: 未インストール
- **必要なもの**: Android NDK + SDK + Java 17 + Gradle + 実機 (or エミュレータ)
- **作業内容**:
  - NDK インストール (`sdkmanager --install "ndk;27.0.12077973"`)
  - `cargo ndk -t arm64-v8a build -p miasma-ffi` で FFI ビルド
  - Java 17 + Gradle + SDK でフル APK ビルド
  - `android-staged-validation.md` Stage 1-4
- **工数**: 3-5日
- **ブロッカー**: NDK/SDK インストール + Java 17

---

## P1 — High (公開ベータ前)

### P1-1: 制限なしネットワークでの非ローカルピア接続検証

- **種別**: 検証/環境
- **現状**: GlobalProtect が outbound QUIC UDP をブロック。GitHub Actions runner への接続は HandshakeTimedOut
- **必要なもの**: 以下のいずれか:
  - (a) GlobalProtect 無効のネットワーク
  - (b) 公開 VPS に Miasma ノードをデプロイ
  - (c) WSS トランスポートで公開サーバ経由接続
- **作業内容**:
  - 接続確立
  - 双方向 retrieve 検証
  - directed sharing 検証
  - relay circuit fallback 実地テスト (3ノードトポロジ)
- **工数**: 2-4日 (環境確保後)
- **ブロッカー**: ネットワーク環境

### P1-2: 大ファイル堅牢性検証

- **種別**: 検証
- **現状**: IPC 経由 directed sharing は ~4MiB 制限あり (文書化済)。通常 dissolve/retrieve の大ファイル限界は未検証
- **作業内容**:
  - 10MB, 100MB, 1GB ファイルの dissolve/retrieve テスト
  - メモリ使用量プロファイリング
  - ストリーミング retrieve の実地検証
  - IPC サイズ制限の workaround or ドキュメント化
- **工数**: 2-3日

### P1-3: 外部セキュリティ監査の準備

- **種別**: セキュリティ
- **現状**: 内部セキュリティ修正 5件 (VULN-001〜005) 完了。外部監査未実施
- **作業内容**:
  - 脅威モデルドキュメント整備 (README に概要あり、詳細版が必要)
  - 攻撃面の明示的列挙
  - 暗号実装のレビュー準備 (BBS+, onion, ECDH, AES-GCM)
  - 監査会社選定・発注
- **工数**: 監査準備 3-5日、監査自体 2-4週間 (外部依存)
- **コスト**: 暗号+P2P プロトコル監査: $30,000-80,000 USD

### P1-4: クラッシュリカバリ・異常系の体系的テスト ✅ COMPLETE (2026-04-01)

- **種別**: 品質
- **現状**: **完了** — 起動時衛生処理 + 21件のクラッシュリカバリテスト追加
- **実装内容**:
  - **起動時衛生処理** (`store.rs`):
    - 孤立 `.tmp` ファイル自動クリーンアップ (data_dir + shares/)
    - `store_index.json` 破損/欠損時のディスクからのインデックス自動再構築
  - **Store クラッシュリカバリテスト** (11件):
    - `corrupted_index_falls_back_to_empty` — インデックス破損→再構築→全shares読取可
    - `missing_index_rebuilt_from_share_files` — インデックス欠損→再構築
    - `orphaned_tmp_files_cleaned_on_open` — .tmp クリーンアップ確認
    - `master_key_wrong_length_fails` — 16byte key → エラー
    - `master_key_empty_file_fails` — 0byte key → エラー
    - `shares_dir_deleted_recreated_on_open` — shares/ 消失→再作成
    - `partial_share_write_does_not_corrupt_index` — .tmp 残骸 + 正常share
    - `truncated_share_file_returns_error` — 切り詰めshare → 復号エラー
    - `multiple_shares_survive_index_corruption` — 5shares × インデックス破損→全復元
    - `index_and_shares_dir_both_missing_starts_fresh` — master.key のみ→新規起動
  - **WAL クラッシュリカバリテスト** (7件):
    - `wal_with_corrupt_lines_skips_bad_entries` — 不正行スキップ
    - `empty_wal_file_handled_gracefully` — 空WAL
    - `wal_with_only_whitespace_handled` — 空白のみWAL
    - `wal_truncated_last_line_recovers` — 書き込み中断(末尾切断)
    - `wal_tmp_left_over_does_not_corrupt` — compact中断の.tmp残骸
    - `no_wal_no_legacy_starts_fresh` — WALなし→新規
  - **統合クラッシュリカバリテスト** (3件, adversarial_test.rs):
    - `crash_recovery_store_index_corruption_rebuilds`
    - `crash_recovery_directed_inbox_missing_envelope`
    - `crash_recovery_directed_envelope_corrupt_json`
- **テスト数**: 776 (全通過、0失敗) — 前回 727 から +49

### P1-5: 外部テスター配布パイプライン

- **種別**: リリース
- **現状**: `windows-broader-tester-expansion.md` 定義済だが未実行
- **作業内容**:
  - 配布チャネル確立 (GitHub Releases + 直接配布)
  - テスターガイド作成
  - フィードバック収集パイプライン
  - インストール/アンインストールの非開発マシン検証
- **工数**: 2-3日
- **前提**: P0-1 (コード署名) 完了後

---

## P2 — Medium (プロダクションリリース前)

### P2-1: iOS ビルド・実機検証

- **種別**: モバイル
- **現状**: Swift ソース 7ファイル完成。ビルド未実行 (macOS + Xcode 必要)
- **必要なもの**: macOS + Xcode + iPhone
- **作業内容**:
  - `ios-staged-validation.md` 全ステージ
  - SwiftUI InboxView 実機動作確認
  - Windows→iOS directed sharing 検証
- **工数**: 3-5日
- **ブロッカー**: macOS 開発環境

### P2-2: Onion Phase 2 — 実リレーノード経由ルーティング ✅ COMPLETE (2026-04-01)

- **種別**: プロトコル/コア
- **現状**: **完了** — Phase 2 ネットワーク実装完成
- **実装内容**:
  - **`NetworkOnionDhtExecutor`** (`executor.rs`): `OnionAwareDhtExecutor` の Phase 2 実装
    - `DhtHandle::relay_onion_info()` からリレーディレクトリ取得
    - `OnionPacketBuilder::build()` で 2-hop パケット構築
    - `DhtHandle::send_onion_request()` で実 libp2p 経由送信 (R1→R2→Target)
    - `decrypt_response()` で 2層応答復号
    - `put()` / `get()` で DHT PUT/GET をオニオンラップ
  - **coordinator の retrieve_via_onion() はすでに Phase 2 パス使用** (既存確認):
    - `send_onion_request()` → 実 libp2p QUIC → R1 → Forward → R2 → Deliver → Target
    - `OnionPacketBuilder::build_e2e()` で E2E 暗号化
    - 3層応答復号 (r1_return_key, r2_return_key, session_key)
  - **exports**: `NetworkOnionDhtExecutor` を lib.rs, network/mod.rs, network/dht.rs からエクスポート
  - **テスト**: `onion_phase2_network_executor_type_exists` — 型検証 + trait bound 確認
- **残作業**: 実ネットワーク上での 3ノードトポロジ検証 (P2-8 に統合)

### P2-3: ブートストラップ信頼の本番化

- **種別**: プロトコル/セキュリティ
- **現状**: ベータ段階 — 「全 Verified ピア = 発行者」というブートストラップ仮定。本番では不適切
- **作業内容**:
  - ハードコードされた信頼アンカー or 署名付きブートストラップリスト
  - 信頼アンカーのローテーション手順
  - Sybil 攻撃耐性のブートストラップ検証
- **工数**: 3-5日

### P2-4: 自動アップデート機構

- **種別**: リリース/UX
- **現状**: MSI major-upgrade は対応済。自動チェック/ダウンロード/適用は未実装
- **作業内容**:
  - バージョンチェック API (GitHub Releases or 自前)
  - ダウンロード + 署名検証
  - デスクトップ GUI に「更新あり」通知
  - サイレントアップデート or ユーザー確認
- **工数**: 3-5日

### P2-5: Android Keystore 統合テスト

- **種別**: モバイル/セキュリティ
- **現状**: コード完成 (wrap-on-startup, unwrap-on-restart)。実機でのキーストア動作未検証
- **作業内容**:
  - 実機で master.key のキーストアラッピング検証
  - キーストア紛失時の挙動確認
  - distress wipe でのキーストア blob 削除検証
- **工数**: 1-2日
- **前提**: P0-3 (Android 実機ビルド) 完了後

### P2-6: 実インターネット規模検証

- **種別**: 検証
- **現状**: 最大 2 ピアでのみ検証。10+ ピアでのルーティング・レプリケーション挙動は未知
- **作業内容**:
  - 5-10 ノードの分散テスト環境構築 (VPS or コンテナ)
  - DHT ルーティング収束時間の計測
  - レプリケーション成功率の計測
  - PoW difficulty の自動調整挙動の検証
  - 負荷テスト (同時 dissolve/retrieve)
- **工数**: 5-10日
- **ブロッカー**: 複数ノードのインフラ

### P2-7: ドキュメント・オンボーディング品質

- **種別**: ドキュメント
- **現状**: TROUBLESHOOTING.md (8セクション)、README.md (脅威モデル・制限記載)。ユーザーガイドは未整備
- **作業内容**:
  - Getting Started ガイド
  - Directed sharing ユーザーガイド
  - ネットワーク構成ガイド (mDNS, bootstrap, proxy)
  - API ドキュメント (HTTP bridge)
  - FAQ
- **工数**: 3-5日

### P2-8: Relay circuit fallback 実地テスト

- **種別**: 検証
- **現状**: ADR-010 Part 2 コード完成 (8テスト)。実ネットワークでの 3ノードトポロジテスト未実施
- **作業内容**:
  - 3ノード構成: Peer A ↔ Relay ↔ Peer B (A-B 直接不可)
  - directed sharing over relay circuit 検証
  - relay trust tier 昇格の実地確認
  - 診断出力 (DirectedRelayStats) の実地確認
- **工数**: 2-3日
- **前提**: P1-1 (非ローカル環境) or ローカル 3ノード環境

---

## P3 — Low (プロダクション品質向上)

### P3-1: 定常トラフィックシェーピング

- **種別**: プライバシー
- **現状**: 固定サイズパディング (8KiB) のみ。トラフィック分析によるアクティビティ相関は可能
- **作業内容**:
  - カバートラフィック生成 (一定レートのダミーパケット)
  - タイミングパディング
  - 送受信パターンの均一化
- **工数**: 5-10日

### P3-2: Web/PWA ネットワーク機能

- **種別**: Web
- **現状**: local-only スコープ決定済。ネットワーク取得・ピア発見は意図的に未実装
- **作業内容** (将来実装する場合):
  - WebRTC データチャネル or WebSocket 中継
  - 本番鍵管理 (WebCrypto API)
  - ブラウザ互換性テスト
- **工数**: 10-20日
- **注意**: アーキテクチャ決定が先 (WebRTC vs relay vs companion)

### P3-3: Android/iOS i18n (国際化)

- **種別**: モバイル/UX
- **現状**: Windows は EN/JA/ZH-CN 対応。モバイルは英語のみ
- **作業内容**:
  - Android: strings.xml の多言語化
  - iOS: Localizable.strings の多言語化
- **工数**: 2-3日

### P3-4: Android/iOS 診断エクスポート

- **種別**: モバイル/診断
- **現状**: Windows のみ「Save Report」ボタンあり。モバイルは未対応
- **作業内容**:
  - DaemonStatus → テキストレポート生成
  - 共有シートへの出力
- **工数**: 1-2日

### P3-5: CI/CD パイプライン強化

- **種別**: インフラ
- **現状**: cargo test + cargo audit は CI にあり。以下は未整備:
  - クロスプラットフォームビルド (Linux musl, Android ARM64)
  - 自動リリース作成
  - ベンチマーク回帰検出
- **工数**: 3-5日

### P3-6: 運用監視・テレメトリ基盤

- **種別**: インフラ/運用
- **現状**: CLI diagnostics + ログのみ。中央集約なし
- **作業内容**:
  - opt-in 匿名テレメトリ
  - クラッシュレポート収集
  - ネットワーク健全性ダッシュボード
- **工数**: 5-10日

---

## P4 — Deferred (明示的スコープ外 / 長期)

### P4-1: Directed sharing over Tor (Tor Hidden Service)

- **種別**: アーキテクチャ
- **理由**: Tor SOCKS5 は outbound-only。libp2p に Tor HS 統合が必要 (`libp2p-tor` は実験的)
- **工数**: 数ヶ月、外部依存リスク大
- **ADR**: ADR-010 で明示的に却下

### P4-2: 非同期メールボックス/インボックス配信

- **種別**: プロトコル設計
- **理由**: store-and-forward モデルは ADR-006 の再設計が必要。anti-misdirection 特性を失う
- **ADR**: ADR-010 で延期

### P4-3: iOS 送信機能

- **種別**: モバイル
- **理由**: retrieval-first 設計は意図的。送信は将来のマイルストーン
- **前提**: iOS 基本検証 (P2-1) 完了後

### P4-4: App Store / Play Store 配布

- **種別**: リリース
- **前提**: P0-3 + P2-1 + P2-5 完了、ストア審査準備
- **工数**: 各ストア 1-2週間 (審査含む)

---

## 優先度サマリ表

| ID | タスク | 種別 | 工数 | ブロッカー |
|----|--------|------|------|------------|
| **P0-1** | コード署名証明書 | リリース | 1-2日+審査 | 証明書申請 |
| **P0-2** | Windows クロスデバイス検証 | 検証 | 2-3日 | 2台目マシン |
| **P0-3** | Android 実機ビルド | モバイル | 3-5日 | NDK+SDK+実機 |
| **P1-1** | 非ローカルピア接続検証 | 検証 | 2-4日 | ネットワーク環境 |
| **P1-2** | 大ファイル堅牢性 | 検証 | 2-3日 | — |
| **P1-3** | 外部セキュリティ監査準備 | セキュリティ | 3-5日+外部 | 監査会社 |
| **P1-4** | ~~クラッシュリカバリ体系テスト~~ | 品質 | ✅完了 | — |
| **P1-5** | 外部テスター配布 | リリース | 2-3日 | P0-1 |
| **P2-1** | iOS ビルド・実機検証 | モバイル | 3-5日 | macOS+Xcode |
| **P2-2** | ~~Onion Phase 2 (実リレー)~~ | プロトコル | ✅完了 | — |
| **P2-3** | ブートストラップ信頼本番化 | セキュリティ | 3-5日 | — |
| **P2-4** | 自動アップデート | UX | 3-5日 | — |
| **P2-5** | Android Keystore 統合テスト | モバイル | 1-2日 | P0-3 |
| **P2-6** | インターネット規模検証 | 検証 | 5-10日 | 複数ノードインフラ |
| **P2-7** | ドキュメント・オンボーディング | ドキュメント | 3-5日 | — |
| **P2-8** | Relay circuit 実地テスト | 検証 | 2-3日 | 3ノード環境 |
| **P3-1** | 定常トラフィックシェーピング | プライバシー | 5-10日 | — |
| **P3-2** | Web/PWA ネットワーク機能 | Web | 10-20日 | アーキ決定 |
| **P3-3** | モバイル i18n | UX | 2-3日 | — |
| **P3-4** | モバイル診断エクスポート | 診断 | 1-2日 | — |
| **P3-5** | CI/CD パイプライン強化 | インフラ | 3-5日 | — |
| **P3-6** | 運用監視基盤 | インフラ | 5-10日 | — |
| **P4-1** | Tor HS 統合 | アーキテクチャ | 数ヶ月 | libp2p-tor |
| **P4-2** | 非同期メールボックス | プロトコル | 数週間 | ADR再設計 |
| **P4-3** | iOS 送信機能 | モバイル | 3-5日 | P2-1 |
| **P4-4** | ストア配布 | リリース | 各1-2週間 | P0-3, P2-1 |

---

## 推奨実行順序

```
P0-1 (コード署名) ──→ P1-5 (外部テスター配布)
         |
P0-2 (Windows クロスデバイス) ──→ P1-2 (大ファイル) ──→ P1-4 (クラッシュリカバリ)
         |
P0-3 (Android 実機) ──→ P2-5 (Keystore統合) ──→ P2-8 (Relay実地)
         |
P1-1 (非ローカル接続) ──→ P2-6 (規模検証) ──→ P2-2 (Onion Phase 2)
         |
P1-3 (監査準備) ──→ 外部監査 ──→ P2-3 (ブートストラップ本番化)
```

**最初の一手**: P0-1 (コード署名) と P0-2 (クロスデバイス検証) は並行可能。
P0-3 (Android) は環境依存のため、環境が整い次第着手。
