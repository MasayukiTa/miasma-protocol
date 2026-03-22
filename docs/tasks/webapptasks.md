## Miasma Web App (WASM PWA) — 実装タスク仕様書

### 目的

macOSデバイスなしでもiOS Safariからmiasmaプロトコルのdissolve/retrieveを利用可能にする。
miasma-coreの暗号パイプライン（AES-256-GCM + Reed-Solomon + Shamir SSS + BLAKE3）をWebAssemblyにコンパイルし、PWAとして提供する。

これはデモやモックアップではない。
プロトコル互換のdissolve/retrieveがブラウザ内で完結する実用ツールを目指す。

### 制約と前提

- miasma-coreをそのままWASMコンパイルすることは不可能（tokio, libp2p, std::fs等の依存）
- 新規crateとして `crates/miasma-wasm` を作成し、暗号パイプラインのみを再実装
- ネットワーク機能（P2P, DHT, onion routing）はスコープ外
- ストレージはブラウザのIndexedDB
- Protocol Version 1との互換性を維持（MID計算、share形式はmiasma-coreと同一）

### アーキテクチャ

```
┌─────────────────────────────────────┐
│           Browser (PWA)             │
│  ┌──────────┐    ┌───────────────┐  │
│  │  Web UI  │◄──►│  miasma-wasm  │  │
│  │ HTML/CSS │    │  (wasm-bindgen)│  │
│  │   JS     │    │               │  │
│  └──────────┘    │ ┌───────────┐ │  │
│                  │ │ dissolve  │ │  │
│  ┌──────────┐    │ │ retrieve  │ │  │
│  │IndexedDB │◄──►│ │ AES-GCM  │ │  │
│  │(shares)  │    │ │ RS codec  │ │  │
│  └──────────┘    │ │ SSS      │ │  │
│                  │ │ BLAKE3   │ │  │
│  ┌──────────┐    │ └───────────┘ │  │
│  │ Service  │    └───────────────┘  │
│  │ Worker   │                       │
│  └──────────┘                       │
└─────────────────────────────────────┘
```

### プロトコル互換性の要件

以下をmiasma-coreと完全に一致させる:
- MID計算: `BLAKE3(plaintext || "k={k},n={n},v=1")`
- 暗号化: AES-256-GCM (鍵32B, nonce 12B, tag 16B)
- 消失訂正: Reed-Solomon (data_shards=10, total_shards=20, shard長は偶数)
- 秘密分散: Shamir (k=10, n=20)
- share形式: `MiasmaShare` struct (bincode serialization)
- coarse verify: `mid_prefix`(8B) + `shard_hash`(BLAKE3)
- full verify: `BLAKE3(plaintext || params) == MID`

---

## Track A: miasma-wasm クレート

### A-1: プロジェクト構成

- `crates/miasma-wasm/Cargo.toml` を作成
- 依存: wasm-bindgen, serde, serde_json, bincode, blake3, aes-gcm, sharks, reed-solomon-simd, rand, zeroize, bs58, getrandom(js feature), web-sys, js-sys
- ターゲット: `wasm32-unknown-unknown`
- crate-type: `cdylib`
- workspace membersに追加

### A-2: 暗号パイプライン実装

miasma-coreの以下を移植（直接依存せず再実装）:
1. `crypto/aead.rs` → AES-256-GCM encrypt/decrypt
2. `crypto/sss.rs` → Shamir split/combine
3. `crypto/rs.rs` → Reed-Solomon encode/decode
4. `crypto/hash.rs` → BLAKE3 ContentId
5. `pipeline.rs` → dissolve/retrieve
6. `share.rs` → MiasmaShare + ShareVerification
7. `error.rs` → MiasmaError (WASM向け簡略版)

### A-3: wasm-bindgen API設計

```rust
#[wasm_bindgen]
pub fn dissolve_text(plaintext: &str) -> Result<JsValue, JsError>;
// Returns: { mid: string, shares: MiasmaShare[] (as JSON) }

#[wasm_bindgen]
pub fn dissolve_bytes(data: &[u8]) -> Result<JsValue, JsError>;

#[wasm_bindgen]
pub fn retrieve_from_shares(mid: &str, shares_json: &str) -> Result<Vec<u8>, JsError>;

#[wasm_bindgen]
pub fn verify_share(share_json: &str, mid: &str) -> bool;

#[wasm_bindgen]
pub fn parse_mid(mid: &str) -> Result<JsValue, JsError>;
```

### A-4: WASM固有の対応

- `getrandom` crateに `features = ["js"]` → `crypto.getRandomValues()` 経由でOsRng動作
- `SystemTime::now()` → `js_sys::Date::now()` でタイムスタンプ取得
- `reed-solomon-simd`: WASM環境ではSIMDフォールバック（pure Rust）で動作確認
- `std::collections::HashMap` → そのまま使用可（WASM対応）

---

## Track B: Web UI 実装

### B-1: ファイル構成

```
web/
├── index.html          # SPA エントリポイント
├── css/
│   └── style.css       # 全スタイル
├── js/
│   ├── app.js          # メインアプリロジック
│   ├── storage.js      # IndexedDB操作
│   └── i18n.js         # 国際化 (ja/en)
├── sw.js               # Service Worker
├── manifest.json       # PWA マニフェスト
└── pkg/                # wasm-pack出力 (gitignore)
```

### B-2: 画面設計

**ホーム画面**
- Dissolve / Retrieve の2つのメインアクション
- ローカルshare数の表示
- 言語切替 (EN/JA)

**Dissolve画面**
- テキスト入力エリア (textarea)
- ファイルドロップゾーン (drag & drop + ファイル選択)
- パラメータ設定 (k/n、デフォルト10/20)
- 実行ボタン → プログレス表示
- 結果: MID表示 + コピーボタン
- shares自動保存 (IndexedDB) + エクスポートボタン (.miasma ファイル)

**Retrieve画面**
- MID入力フィールド (ペースト / QR読み取り将来対応)
- ローカルshare自動検索 + 手動インポート
- share充足状況 (k/n プログレスバー)
- 復元ボタン → 結果表示
- テキスト: 直接表示 + コピー
- バイナリ: ダウンロードリンク

**設定画面**
- ストレージ使用量
- share一括削除
- 言語切替
- バージョン情報 + プロトコルバージョン

### B-3: UI/UXデザイン方針

- ダークテーマ（プライバシーツールとしての視覚的アイデンティティ）
- モバイルファースト（iOS Safari 16+が主ターゲット）
- フレームワークなし（バニラJS + CSS Custom Properties）
- CSS Grid / Flexbox によるレスポンシブ
- アニメーション: dissolve時のパーティクル風エフェクト（CSS only）
- フォント: system-ui, -apple-system（CJK対応）
- カラーパレット: #0a0a0f (bg) / #1a1a2e (card) / #7c3aed (accent/purple) / #22d3ee (secondary/cyan)

### B-4: IndexedDB ストレージ

```javascript
// DB: "miasma-web", version 1
// Object Store: "shares"
//   keyPath: compound key [mid_prefix_hex, slot_index]
//   indexes: mid_prefix_hex, timestamp
// Object Store: "metadata"
//   keyPath: mid
//   fields: mid, created_at, original_len, data_shards, total_shards, label
```

---

## Track C: PWA構成

### C-1: manifest.json

- name: "Miasma Web"
- short_name: "Miasma"
- display: "standalone"
- theme_color: "#0a0a0f"
- background_color: "#0a0a0f"
- start_url: "/index.html"
- icons: SVGベースのアイコン生成

### C-2: Service Worker

- WASMバイナリのキャッシュ（Cache API）
- オフライン動作（全静的アセット + WASMをprecache）
- バージョニング（cache busting）

### C-3: ホスティング

- GitHub Pages対応（`/web` ディレクトリまたは `gh-pages` ブランチ）
- CSPヘッダ: `script-src 'self' 'wasm-unsafe-eval'`
- CORS不要（全処理がクライアントサイド）

---

## セキュリティ上の問題点

### 重大 (Critical)

1. **鍵素材のメモリ管理**
   - ブラウザJS/WASMヒープでは`Zeroizing`の保証が弱い
   - GCによる遅延解放、メモリスワップへの露出リスク
   - **対策**: WASM linear memoryで鍵を保持し、使用後に明示的ゼロクリア。完全なゼロ化保証はブラウザでは不可能であることをドキュメントに明記
   - **残存リスク**: ブラウザのGC/JIT最適化により、鍵のコピーがJS heapに残る可能性

2. **IndexedDBの暗号化不在**
   - shareデータは暗号化なしでIndexedDBに格納される
   - 同一オリジンの他のスクリプト、ブラウザ拡張機能からアクセス可能
   - **対策**: Phase 1ではこの制約を受け入れる。shareは個別には無意味（k個必要）なことを説明。将来的にはWeb Crypto APIでローカル暗号化を追加

3. **サプライチェーン攻撃**
   - WASMバイナリがHTTP経由で配信される場合、改竄リスク
   - **対策**: HTTPS必須、Subresource Integrity (SRI) ハッシュをHTMLに埋め込み、Service Workerでキャッシュ整合性検証

### 高 (High)

4. **エントロピー品質**
   - `crypto.getRandomValues()`（CSPRNG）経由で`getrandom`が動作
   - ブラウザの実装に依存するため、品質はOS直接呼び出しより不透明
   - **対策**: 主要ブラウザ(Safari, Chrome, Firefox)はOS CSPRNGを使用しており実用上問題なし。ドキュメントに記載

5. **サイドチャネル**
   - WASM実行のタイミング特性はネイティブと異なる
   - JITコンパイルによりタイミングが非決定的
   - **対策**: AES-GCMはconstant-time実装（aes-gcm crateのsoft feature）。SSS/RSは情報理論的に安全なため問題少。miasma-coreと同等レベル

6. **XSS経由のshare窃取**
   - XSS脆弱性があれば、IndexedDB内のshareにアクセス可能
   - **対策**: CSP strict設定、外部スクリプト読み込みゼロ、inline script禁止

### 中 (Medium)

7. **オフライン復元の信頼性**
   - Service Worker更新メカニズムに依存
   - キャッシュ破損時にWASMが利用不能になるリスク
   - **対策**: WASMバイナリのSRI検証、キャッシュ失敗時のフォールバック再取得

8. **ブラウザバージョン依存**
   - WebAssembly, IndexedDB, Service Worker, crypto.getRandomValues()のサポート
   - iOS Safari 16+で全機能利用可能（ターゲット範囲）
   - **対策**: 起動時のfeature detection + 非対応時の明確なエラーメッセージ

9. **share形式の互換性検証不足**
   - WASM版で生成したshareがデスクトップ版で復元できるか（またはその逆）の検証が必要
   - **対策**: 既知のテストベクターでcross-platform検証テストを実装

### 低 (Low)

10. **IndexedDB容量制限**
    - Safari: 1GBまで（ユーザー許可後拡張）
    - 大量のshare保存には向かない
    - **対策**: ストレージ使用量表示、古いshareの自動削除オプション

11. **PWAインストール体験**
    - iOS Safariでは「ホーム画面に追加」が分かりにくい
    - **対策**: インストールガイドバナーを表示

---

## 既知の制限事項

1. **ネットワーク非対応**: P2P share交換、DHT検索はできない。shareの受け渡しは手動（コピー、ファイル、QR等）
2. **大容量制限**: ブラウザメモリ制約により、実用上は~100MB程度まで
3. **バックグラウンド不可**: dissolve/retrieve処理中にタブを閉じると中断
4. **セキュアエンクレーブ不使用**: Web Crypto APIのnon-extractable keyは使用可能だが、miasma-coreのパイプラインとは非互換
5. **監査未実施**: ネイティブ版と同様、セキュリティ監査は未実施

---

## 実装順序

1. **A-1 → A-2 → A-3**: miasma-wasm crateを先に完成させる
2. **A-4**: WASM特有の対応（getrandom js, timestamp）
3. **B-1 → B-3**: Web UI骨格 + スタイリング
4. **B-2**: 各画面実装（Dissolve → Retrieve → Settings → Home）
5. **B-4**: IndexedDB統合
6. **C-1 → C-2**: PWA化
7. Cross-platform互換テスト

---

## 完了基準

- [ ] `wasm-pack build` が成功する
- [ ] dissolve → retrieve のラウンドトリップがブラウザ内で動作する
- [ ] 生成されるMIDがmiasma-coreと同一（テストベクターで検証）
- [ ] share形式がbincode互換（miasma-coreのshare.to_bytes()と相互運用可能）
- [ ] iOS Safari 16+で全フロー動作確認
- [ ] PWAとしてオフラインインストール可能
- [ ] セキュリティ制約がUI上およびドキュメントで明示されている
- [ ] IndexedDBへのshare保存/復元が動作する
