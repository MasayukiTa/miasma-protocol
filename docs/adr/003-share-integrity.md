# ADR-003: Share 整合性検証方式

**ステータス**: 決定済み
**日付**: 2026-03-16
**決定者**: プロジェクト初期設計

---

## コンテキスト

Miasma の retrieval では複数ノードから Share を収集し、k 個以上揃った時点で:
1. Reed-Solomon によるシャード再構築
2. SSS による K_enc 鍵復元
3. AES-256-GCM 復号
4. BLAKE3 ハッシュ検証（vs MID）

を行う。

**問題**: K_enc は SSS 分散されているため、k 個集まるまで復元不可。
つまり **k 個収集前に MAC 検証（K_tag を使った全 Share 検証）は不可能**。
偽造 Share を k 個収集前に棄却できないと、攻撃者は大量の偽造 Share を投入し
再構築を妨害できる（DoS / griefing 攻撃）。

### 検討した3つの選択肢

| 選択肢 | 概要 |
|--------|------|
| ① shard hash + MID prefix 粗検証 | 各 Share に `BLAKE3(shard_data)` のコミットメントを付与。k 個前でも偽造を棄却可。 |
| ② MAC 鍵を SSS と独立管理 | K_tag を別経路で配布。全 Share を即時 MAC 検証可能だが、K_tag 配布経路の設計が必要。 |
| ③ rate limit / redundancy / reputation で対処 | 個別 Share 検証なし。ネットワーク対策のみで偽造に対応。 |

## 決定

**選択肢 ①: 公開検証可能な shard hash + MID prefix による粗検証を採用する。**

## 根拠

1. **情報理論的プライバシーを損なわない**: `BLAKE3(shard_data)` はシャードデータのコミットメントであり、コンテンツや K_enc を漏らさない。
2. **k 個収集前に偽造 Share を棄却できる**: 攻撃者が偽造 Share を投入しても、shard hash の不一致で即座に検出・棄却可能。
3. **実装がシンプル**: 追加の鍵管理インフラが不要。dissolution 時に hash を計算して Share に埋め込むだけ。
4. **選択肢 ② のリスク回避**: K_tag を独立管理すると、その配布経路が新たな攻撃対象になり得る。K_tag の露出が SSS 設計の情報理論的保証を損なう可能性がある。

## 実装仕様

### Share フォーマット (`MiasmaShare`)

```rust
pub struct MiasmaShare {
    pub version: u8,            // プロトコルバージョン (現在: 1)
    pub mid_prefix: [u8; 8],    // BLAKE3(content || params) の先頭 8 バイト
    pub slot_index: u16,        // Reed-Solomon シャードのインデックス (0..n-1)
    pub shard_data: Vec<u8>,    // RS 符号化済みシャードデータ (暗号化済み)
    pub key_share: Vec<u8>,     // Shamir 秘密分散された K_enc の断片
    pub shard_hash: [u8; 32],   // BLAKE3(shard_data) — 粗検証用コミットメント
    pub timestamp: u64,         // Unix タイムスタンプ (秒)
}
```

### 粗検証ロジック（k 個収集前）

```rust
/// k 個収集前に実行できる早期棄却検査。
/// K_enc が復元できないため MAC 検証は不可。
/// shard_hash と mid_prefix の一致のみ確認する。
pub fn coarse_verify(share: &MiasmaShare, expected_mid_prefix: &[u8; 8]) -> bool {
    // 1. MID prefix チェック（正しいコンテンツの Share か）
    if share.mid_prefix != *expected_mid_prefix {
        return false;
    }
    // 2. shard_data のハッシュチェック（データ改竄がないか）
    let computed = blake3::hash(&share.shard_data);
    computed.as_bytes() == &share.shard_hash
}
```

### 完全検証ロジック（k 個収集後）

k 個収集後は SSS で K_enc を復元し、AES-256-GCM 復号を試みる。
復号成功 + BLAKE3(再構築コンテンツ) == MID で完全性を保証する。

```rust
// K_tag は K_enc から派生させる（K_enc が復元されて初めて検証可能）
// K_tag = BLAKE3_keyed(K_enc, b"miasma-mac-key-v1")
```

### 制約の明示（コードコメント）

```rust
// SECURITY NOTE (ADR-003):
// K_tag は K_enc から派生するため、K_enc が SSS で復元されるまで
// （= k 個の Share が揃うまで）MAC 検証は不可能。
// k 個収集前の偽造 Share 棄却は shard_hash + mid_prefix の粗検証のみで行う。
// これは意図的な設計トレードオフであり、バグではない。
```

## テストベクトル

実装後、以下のテストケースで検証すること:

1. 正規 Share → `coarse_verify` が `true` を返す
2. `shard_data` を 1 バイト改竄した Share → `coarse_verify` が `false` を返す
3. 別コンテンツの `mid_prefix` を持つ Share → `coarse_verify` が `false` を返す
4. k 個の正規 Share + 偽造 Share 混在 → 偽造 Share が棄却され、k 個の正規 Share で復元成功
