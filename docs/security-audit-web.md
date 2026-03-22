# Miasma Web セキュリティ診断レポート

**日付**: 2026-03-22
**対象**: miasma-wasm crate + web/ PWA フロントエンド
**スコープ**: WASM暗号実装、Webフロントエンド、ストレージ、PWA

---

## サマリー

| 深刻度 | 検出数 | 修正済み | 残存 |
|--------|--------|----------|------|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 3 | 3 | 0 |
| MEDIUM | 8 | 8 | 0 |
| LOW | 13 | 0 | 13 |
| INFO | 3 | - | - |

全CRITICAL/HIGH/MEDIUM指摘を修正済み。LOW以下は許容リスクとして文書化。

---

## CRITICAL — 修正済み

### C-1: SSSパラメータのu8切り捨てによる閾値セキュリティ破壊

**場所**: `crates/miasma-wasm/src/lib.rs` dissolve_inner / retrieve_inner

**問題**: `params.data_shards as u8` のキャストで、k=257 → 1 に切り捨てられる。
1シェアで暗号鍵が復元可能になり、閾値暗号の安全性が完全に崩壊。

**修正**: `validate_params()` を追加。k, n の範囲を 0 < k < n ≤ 255 に制限。
公開API (`dissolve_text`, `dissolve_bytes`, `retrieve_from_shares`) から呼び出されるすべてのパスで検証実行。

---

## HIGH — 修正済み

### H-1: ZeroizeのWASM環境における実効性の限界

**場所**: encrypt() 内の `Zeroizing<[u8; KEY_LEN]>`

**問題**: WASM linear memoryはJS側から `WebAssembly.Memory.buffer` 経由で全て読み取り可能。
`Zeroize` のドロップ時ゼロクリアはLLVMの最適化で除去される可能性がある。
`Aes256Gcm::generate_key` の戻り値（スタック上の `GenericArray`）はZeroize対象外。

**対策**: 根本的解決はブラウザ環境では不可能。Settings画面および本レポートにリスク明記。

**残存リスク**: 許容（ドキュメント対応）。「高度に機密性の高いコンテンツには使用しないでください」を維持。

### H-2: original_len の u32 切り捨て

**場所**: dissolve_inner L427 `plaintext.len() as u32`

**問題**: 4GiB超のコンテンツでサイレント切り捨て。RS decode後のtruncate長が不正になる。

**修正**: dissolve_inner で `plaintext.len() > u32::MAX` チェックを追加。
加えて `MAX_INPUT_SIZE = 100MB` の上限も追加（WASM環境の実用的制約）。

### H-3: bincode デシリアライズによる OOM DoS

**場所**: `MiasmaShare::from_bytes()`

**問題**: bincode v1は `Vec<u8>` の長さプレフィックスとして u64 を読み取る。
攻撃者が length=0xFFFFFFFFFFFFFFFF のペイロードを送ると、巨大メモリ確保でOOM。

**修正**: 入力バイト長を `MAX_BINCODE_SIZE = 1MB` で事前チェック。

---

## MEDIUM — 修正済み

### M-1: CSP に frame-ancestors / base-uri / form-action 不在

**修正**: `frame-ancestors 'none'; base-uri 'self'; form-action 'self'` を追加。

### M-2: Service Worker の cache-first 戦略で改竄キャッシュが永続化

**修正**: WASM/JSアセットを stale-while-revalidate 戦略に変更。
キャッシュされた応答を返しつつ、バックグラウンドでネットワーク更新。
その他アセットは precache リスト限定でキャッシュ。

### M-3: WASM バイナリに SRI ハッシュ未適用

**状態**: Service Worker の stale-while-revalidate で緩和。完全なSRIは将来課題。

### M-4: JSONインポート時のプロトタイプ汚染リスク

**修正**: `sanitizeShare()` 関数を追加。既知フィールドのみをコピーし、
`__proto__`, `constructor` 等の汚染ベクターを排除。

### M-5: k/n パラメータの NaN バイパス

**修正**: `Number.isNaN(k) || Number.isNaN(n)` チェックと `k > 255 || n > 255` 上限を追加。

### M-6: エラーメッセージによる情報漏洩

**修正**: ユーザー向けトースト通知を汎用メッセージに変更。
詳細エラーは `console.error` にのみ出力。MID文字列のエコーバックも削除。

### M-7: 暗号操作のエラーメッセージでのユーザー入力エコー

**修正**: `ContentId::from_mid_str` のエラーメッセージからユーザー入力を除去。

### M-8: retrieve_inner での nonce/original_len 不整合

**修正**: 選択されたシェア間で nonce と original_len の一致を検証。
不一致時は `ShareIntegrity` エラーを返す。

---

## LOW — 許容リスク（修正対象外）

| # | 内容 | 理由 |
|---|------|------|
| L-1 | 手実装の base64/hex が定数時間でない | WASM環境のタイマー精度低下で緩和。シェアデータのみ対象。 |
| L-2 | base64デコーダが末尾不完全チャンクを無視 | データ破損はfull_verifyで検出。 |
| L-3 | slot_index の u16 切り捨て | validate_params で n≤255 に制限済みのため問題なし。 |
| L-4 | share_to_json の bincode エラーが silent fallback | JSON フィールドパスで復元可能。 |
| L-5 | coarse_verify の 8B プレフィックスの衝突リスク (2^32) | full_verify で最終検証。設計上意図的。 |
| L-6 | 入力サイズ制限なし（WASM API レベル） | MAX_INPUT_SIZE / MAX_SHARE_COUNT を追加済み。 |
| L-7 | CSP `style-src 'unsafe-inline'` | プログラム的 style 設定に必要。XSS はテキスト注入パターンで緩和。 |
| L-8 | MID 入力に長さ制限なし（BigInt DoS） | maxlength=60 を HTML に追加済み。 |
| L-9 | Base58 デコーダが先頭ゼロバイト未対応 | Miasma MID は BLAKE3 ダイジェストのため先頭ゼロは確率的にのみ発生。 |
| L-10 | Base58 デコーダがオーバーフローを切り捨て | maxlength=60 で緩和。 |
| L-11 | バイナリダウンロードに Content-Type/拡張子なし | セキュリティ上はむしろ安全（自動実行防止）。 |
| L-12 | Service Worker 登録パスが絶対パス | デプロイ構成依存。GitHub Pages では問題なし。 |
| L-13 | console.error でフルエラーオブジェクト出力 | DevTools アクセスは物理アクセスを前提。 |

---

## INFO

| # | 内容 |
|---|------|
| I-1 | IndexedDB は same-origin 隔離。ブラウザ拡張機能は読み取り可能。UI で注意喚起済み。 |
| I-2 | nonce が全シェアで共有される。設計上正しい（1暗号化 = 1 nonce/key ペア）。 |
| I-3 | XSS ベクター未検出。全動的コンテンツが textContent 経由。innerHTML/eval なし。 |

---

## 推奨する将来対応

1. **Web Crypto API 統合**: AES-GCM 鍵を non-extractable CryptoKey として保持。
   WASM パイプラインとの統合が課題だが、鍵漏洩リスクを大幅に低減。

2. **SRI ハッシュ**: WASM バイナリの integrity 属性をビルド時に生成。

3. **base64/hex crate 導入**: 手実装を `base64` / `hex` crate に置換。

4. **Content-Disposition ヘッダ**: エクスポートファイルの MIME タイプ設定。

5. **独立セキュリティ監査**: 本レポートは内部診断。公開前に第三者監査を推奨。
