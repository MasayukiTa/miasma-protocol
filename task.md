# Miasma Protocol — タスク一覧

PRD ([miasma-prd.md](file:///c:/Users/M118A8586/Desktop/github_lab/miasma-protocol/miasma-prd.md)) および技術調査レポート ([Research-backed_Master_Design_Doc.md](file:///c:/Users/M118A8586/Desktop/github_lab/miasma-protocol/Research-backed_Master_Design_Doc.md)) から抽出したタスク。

---

## Phase 0: アーキテクチャ決定（実装開始前必須）

> **実装着手前にこれらを決定・記録すること。未決定のまま Phase 1 に進まない。**

### 0. Architecture Decision Records (ADR)

- [ ] **ADR-001: トランスポート層選定** — libp2p 内蔵の QUIC transport（`libp2p-quic`クレート）に一本化するか、`quinn` + `rustls` 独自スタックにするか決定。接続管理の一元化方針（libp2p connection manager のみ、または quinn connection との併存）を1行で明記し `docs/adr/001-transport.md` に記録する。
- [ ] **ADR-002: DHT + Onion API 境界設計** — DHT の put/get を直接呼ばず `onion-aware query executor` を介してのみ呼べるインターフェースを定義。「誰が問い合わせたか」の抽象化責務・リクエスト/レスポンスの再パッケージ責務を明記し `docs/adr/002-dht-onion-boundary.md` に記録する。
- [ ] **ADR-003: Share 整合性検証方式** — MAC鍵（K_tag）の配布・検証タイミングを下記3択から選び記録する。K_enc は SSS 分散されるため k 個集まるまで復元不可という制約を踏まえた設計であること。選択肢：①公開検証可能な shard hash + MID prefix による粗検証、②MAC鍵を SSS とは独立して管理（漏洩/リンク性の設計が必要）、③k 個収集前は rate limit / redundancy / reputation で対処。`docs/adr/003-share-integrity.md` に記録する。

---

## Phase 1: MVP（9ヶ月目標）

### 1. プロジェクト初期セットアップ
- [ ] `cargo new miasma-core` でRustプロジェクト作成
- [ ] CI/CD パイプライン構築（再現可能ビルド対応）
- [ ] ライセンスファイル設定（MIT or AGPL）
- [ ] Cargo.toml に依存クレート定義（blake3, sharks, reed-solomon-simd, snow, quinn, libp2p, tokio）

### 2. コア暗号エンジン（Month 1–2）
- [ ] BLAKE3 コンテンツハッシュ実装 — MID生成ロジック (`miasma:<base58(BLAKE3(C || params))>`)
- [ ] AES-256-GCM 暗号化/復号化モジュール実装
- [ ] Shamir's Secret Sharing (SSS) — ハイブリッド方式実装（鍵のみSSS分散、`sharks`クレート使用）
- [ ] Reed-Solomon 消失訂正符号 — エンコード/デコード実装（k=10, n=20デフォルト、`reed-solomon-simd`クレート使用）
- [ ] Share フォーマット定義 (`MiasmaShare` 構造体: version, mid_prefix, slot_index, shard_data, key_share, mac, timestamp)
- [ ] Share 整合性検証方式の決定（ADR-003）と実装:
  - ADR-003 で選択した方式（①公開検証可能な shard hash + MID prefix / ②MAC鍵を SSS と独立管理 / ③rate limit 対処）を実装
  - retrieval 途中での偽造Share早期棄却手段（k 個収集前の粗検証ロジック）を実装
  - K_tag が K_enc 由来 → k 個集まるまで検証不可という制約を設計に明示し、コードコメントに記録
  - 選択方式のテストベクトルを公開（偽造Shareを弾けるか検証）
- [ ] 鍵導出階層の実装（ノードマスターキー → ノードID, DHT署名鍵, セッション鍵）
- [ ] ユニットテスト: 暗号プリミティブ全体のテストベクトル公開
- [ ] ベンチマーク: ARM64でのパフォーマンス測定（BLAKE3 100MB ≤150ms, AES-256-GCM 100MB ≤200ms, RS 100MB ≤300ms）

### 3. libp2pネットワーク層（Month 3–4）
- [ ] **ADR-001 確定**: トランスポート実装方針を確定し `docs/adr/001-transport.md` に記録（libp2p-quic に一本化か、quinn 独自スタックかを選択）
- [ ] **ADR-002 成果物**: DHT I/O API 境界設計（onion-aware） — DHT の put/get を直接呼ばず `onion-aware query executor` を通じてのみ呼べるトレイト/インターフェースを定義・実装（Month 4 の DHT 実装前に完了すること）
- [ ] libp2p ノード初期化とピア接続
- [ ] Kademlia DHT 実装（ルーティングテーブル管理）— **必ず ADR-002 の onion-aware API 境界を通じて呼び出す設計にすること**
- [ ] Noise XX トランスポート暗号化統合（ADR-001 で libp2p 採用の場合のみ実施）
- [ ] QUIC トランスポート設定（ADR-001 決定に従う — `libp2p-quic` クレート使用 or `quinn` + `rustls` 独自スタック）
- [ ] NAT トラバーサル（libp2p relay + QUIC hole-punching）
- [ ] ノードタイプ定義（Light node, Full node, Bridge node, Bootstrap node）
- [ ] ブートストラップノード接続ロジック
- [ ] DHT put/get 操作（MIDメタデータの公開・取得）
- [ ] ピア発見とルーティング

### 4. オニオンルーティング（Month 5）
- [ ] 2ホップオニオン回路の構築ロジック
- [ ] DHTクエリのオニオンルーティング（全クエリが2ホップ以上を経由）
- [ ] Share転送のオニオンルーティング
- [ ] 各Share取得に個別オニオン回路使用（Share間リンク不可化）
- [ ] エフェメラル回路IDの生成と管理

### 5. コンテンツ溶解（Dissolution）パイプライン
- [ ] ファイル入力 → 暗号化 → RS符号化 → SSS鍵分散 → Share生成の統合パイプライン
- [ ] **ファイルサイズ別処理方式の明確化（Phase 1 スコープ定義）**:
  - Phase 1 対象: dissolution（分散）は 1KB〜100GB 対応（大容量はストリーミング I/O）
  - Phase 1 の retrieval（復元）は概ね 1GB 以下のメモリ内処理に限定（100GB の in-memory 復元は非現実的）
  - 100GB ファイルの restoration は Phase 2（Section 16: ストリーミング取得）で対応 — Phase 1 には含めない
- [ ] **アトミック分配プロトコル設計と実装**（P2P での2PC は coordinator 不在・participant churn・partial commit のリスクがあるため、下記を事前決定すること）:
  - **意思決定**: 「P2P 2フェーズコミット」か「best-effort + repair（再配布）」かを選択し記録
  - 2PC を採用する場合（追加タスク）:
    - coordinator の役割と選定ロジック（誰が coordinator になるか）
    - prepare ACK 収集タイムアウト設計
    - commit 再送・回復プロトコル
    - coordinator クラッシュ時の state recovery 手順
    - DHT への publish タイミング（全 Share 配布確認後）
  - best-effort + repair を採用する場合（追加タスク）:
    - 再配布トリガー条件と repair プロトコルの設計
- [ ] Dissolution完了後のMID返却
- [ ] 部分失敗コンテンツの再Dissolution対応

### 6. コンテンツ取得（Retrieval）パイプライン
- [ ] MID指定による取得ロジック
- [ ] オニオン経由のShare収集（ランダム順、k個受信で停止）
- [ ] Reed-Solomon 再構築 + SSS鍵復元
- [ ] BLAKE3ハッシュ検証（再構築コンテンツ vs MID）
- [ ] 平文コンテンツのディスク書き込み禁止（メモリ内のみ復元）— **Phase 1 スコープ: 概ね 1GB 以下が対象。100GB ファイルの復元は Phase 2 ストリーミング取得（Section 16）で対応**
- [ ] 不正/偽造Share検出と拒否（MAC検証）

### 7. ローカル暗号化Shareストア
- [ ] **ローカルストア暗号化設計の決定と実装**（後から変更すると distress wipe 要件と衝突するため、実装前に決定すること）:
  - 鍵保管場所: Android Keystore / iOS Keychain / デスクトップ TPM または保護ファイル鍵（プラットフォーム別に設計）
  - 暗号アルゴリズム: XChaCha20-Poly1305 または AES-256-GCM（選択理由を記録）
  - 暗号化粒度: ファイル単位 or DB ページ単位
  - distress wipe との整合確認: **鍵削除 = 全 Share が瞬時に不可読になる**設計であること（Section 9 と連携）
- [ ] BLAKE3アドレス方式によるShare保管
- [ ] 設定可能なストレージクォータ（モバイル: 500MB, デスクトップ: 10GB）
- [ ] LRU eviction（ストレージ満杯時の自動削除）
- [ ] 帯域幅クォータ管理（モバイル: 100MB/day）
- [ ] Share回転（有効期限/更新）の自動処理

### 8. CLIクライアント（Month 6）
- [ ] `miasma init` — ノード初期化コマンド（ストレージ/帯域幅設定）
- [ ] `miasma dissolve <path>` — ファイル溶解コマンド
- [ ] `miasma get <MID>` — MIDによる取得コマンド
- [ ] `miasma status` — ノード状態表示コマンド
- [ ] `miasma wipe --confirm` — 緊急ワイプコマンド
- [ ] `miasma config` — 設定管理コマンド
- [ ] `miasma daemon` — デーモンモード（systemd対応）
- [ ] Linux / macOS / Windows クロスプラットフォームビルド

### 9. 緊急ワイプ（Distress Wipe）
- [ ] ローカル鍵素材の5秒以内ゼロ化
- [ ] 設定可能な緊急ジェスチャー（モバイル用）
- [ ] ワイプ後もアプリが正常にインストール済みとして表示
- [ ] KeyStore/SecureEnclave レベルの鍵削除

### 10. Androidアプリ（Month 7–8）
- [ ] UniFFI ブリッジ設定（Rust → Kotlin/Java）
- [ ] 最小UI: Dissolve / Retrieve / Status 画面
- [ ] Foreground Service による永続バックグラウンド動作
- [ ] 帯域幅/ストレージクォータのUI設定
- [ ] QRコード読み取り/表示（MID共有用）

### 11. ブートストラップインフラ
- [ ] 3台のブートストラップノードのデプロイ（開発者運用）
- [ ] ブートストラップノード経由の初期DHTルーティングテーブル配布
- [ ] `--bootstrap` フラグによるユーザー指定ブートストラップ対応

### 12. テストとアルファリリース（Month 8–9）
- [ ] 統合テストスイート作成
- [ ] アルファテスト（内部 + 5人の信頼テスター）
- [ ] テストカバレッジ ≥85%
- [ ] パフォーマンスSLO検証（P50取得遅延 ≤45s, 取得成功率 ≥95%）
- [ ] セキュリティテスト（Share偽造率 = 0, ワイプ ≤5s）
- [ ] ベータリリース（技術ユーザー向け公開）

---

## Phase 2: 検閲耐性 + iOS + BT互換（Month 10–18）

### 13. iOSアプリ
- [ ] UniFFI iOSブリッジ構築
- [ ] BGProcessingTask による部分的ネットワーク参加
- [ ] iOSバックグラウンド制限への対応（「パートタイム」参加者モデル）
- [ ] Apple開発者アカウント取得

### 14. トラフィック難読化
- [ ] QUIC + REALITY風 TLSカモフラージュ実装（DPIがCDNへのHTTPSに見える）
- [ ] WebSocket-over-TLS フォールバック（QUIC ブロック時）
- [ ] プラガブルトランスポートインターフェース設計
- [ ] アクティブプロービング耐性テスト

### 15. BitTorrentブリッジ
- [ ] `librqbit` 統合によるBTプロトコル対応
- [ ] マグネットリンク → Miasma MID 変換パイプライン
- [ ] BT info hash ↔ MID マッピングの公開インデックス（オプトイン）
- [ ] Bridge CLI: `miasma bridge --quota 100G`
- [ ] プライバシー保護: バッチ処理 + ランダム遅延、一方向ブリッジ

### 16. ストリーミング取得
- [ ] 大容量ファイルのプログレッシブ取得/再生
- [ ] 固定メモリバッファによるストリーミング再構築

### 17. カバートラフィック
- [ ] 設定可能なダミートラフィック（512B/s〜2KB/s）
- [ ] トラフィックパターン正規化

---

## Phase 3: ネットワーク強化（Month 19–27）

### 18. ZKレピュテーションシステム
- [ ] BBS+ 署名によるベースラインレピュテーション（＜10ms on mobile）
- [ ] 選択的開示による匿名レピュテーション証明
- [ ] Groth16 ZK証明（高価値trustless検証、オプション）

### 19. S/Kademlia Sybil耐性DHT
- [ ] ノードID生成コスト導入によるSybil攻撃耐性
- [ ] 署名付きDHTエントリ

### 20. プロアクティブShare再共有
- [ ] Share保有ノードのオフライン検出
- [ ] 自動再分配プロトコル（チャーン対策）

### 21. セキュリティ監査
- [ ] 第三者セキュリティ監査の実施（v1.0前必須）
- [ ] 形式的匿名性分析（学術連携）
- [ ] 既知の制限事項の文書化更新

### 22. マルチプラットフォームデスクトップGUI
- [ ] クロスプラットフォームGUIアプリケーション開発

---

## 継続的タスク（Phase横断）

### 23. ドキュメンテーション
- [ ] プロトコル仕様書の公開ドキュメント作成
- [ ] 公開API ドキュメントカバレッジ 100%
- [ ] テストベクトルの公開（全暗号操作）
- [ ] 正当な用途の記載（検閲耐性、内部告発、プライベート文書共有）

### 24. 法務・組織
- [ ] 非営利財団設立（Tor Project / Signal Foundation モデル）
- [ ] SSS法的防御のブリーフ公開
- [ ] 暗号技術者によるレビュー（§6 Cryptographic Design）
- [ ] 弁護士相談

### 25. パフォーマンス最適化
- [ ] バッテリー消費: バックグラウンドパッシブ ≤3%/hour (Android)
- [ ] アプリバイナリサイズ ≤60MB（LTO, feature flags）
- [ ] コールドスタート ≤3s
- [ ] プロトコルオーバーヘッド ≤10%（ファイルバイトあたり）
