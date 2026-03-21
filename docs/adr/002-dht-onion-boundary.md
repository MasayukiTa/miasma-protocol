# ADR-002: DHT + Onion API 境界設計

**ステータス**: 決定済み
**日付**: 2026-03-16
**決定者**: プロジェクト初期設計

---

## コンテキスト

DHT (Kademlia) の `put`/`get` を直接呼ぶと、クエリ元ノードの IP アドレスが DHT ルーティングに露出する。
Miasma は「誰が何を問い合わせたか」を隠すためにオニオンルーティングを使用するが、
DHT API と Onion layer の境界が曖昧だと以下のリスクが生じる：

- 実装者が誤って DHT を直接呼び、クエリ元が露出する
- テスト時にオニオン回路をバイパスしてしまう

## 決定

DHT の `put`/`get` を直接呼ぶことを禁止し、
必ず `OnionAwareDhtExecutor` トレイトを介してのみ呼び出せる設計とする。

## 責務の定義

### `OnionAwareDhtExecutor` トレイト

```rust
/// DHT クエリをオニオン回路越しに実行する唯一のエントリーポイント。
/// このトレイトを経由しない DHT I/O は禁止とする。
pub trait OnionAwareDhtExecutor: Send + Sync {
    /// MID メタデータを DHT に公開する（dissolution 完了後に呼ばれる）
    ///
    /// 責務:
    /// - リクエストを 2 ホップ以上のオニオン回路にパッケージする
    /// - 応答を元のオニオン回路経由で受け取り、発信元を抽象化する
    async fn put(&self, mid: &ContentId, metadata: DhtMetadata) -> Result<(), DhtError>;

    /// MID に対応するメタデータを DHT から取得する（retrieval 開始時）
    ///
    /// 責務:
    /// - クエリを 2 ホップ以上のオニオン回路にパッケージする
    /// - 各クエリに独立したエフェメラル回路 ID を使用し、複数クエリ間のリンクを防ぐ
    /// - 応答をアンラップして返す（経路情報は除去済み）
    async fn get(&self, mid: &ContentId) -> Result<Option<DhtMetadata>, DhtError>;
}
```

### 抽象化責務

| 責務 | 担当コンポーネント |
|------|-------------------|
| 「誰がクエリを発行したか」の隠蔽 | `OnionAwareDhtExecutor` 実装 |
| DHT リクエストのオニオンパッケージング | オニオン回路モジュール (`onion::Circuit`) |
| DHT レスポンスのアンラップ | `OnionAwareDhtExecutor` 実装 |
| 複数クエリ間のリンク不可化 | 各クエリに独立エフェメラル回路 ID (`CircuitId`) を割り当て |
| Kademlia ルーティングの実際の実行 | libp2p-kad（`OnionAwareDhtExecutor` の内部でのみ使用） |

### 禁止事項

```rust
// ❌ 禁止: libp2p-kad を直接呼ぶ
swarm.behaviour_mut().kademlia.get_record(key);

// ✅ 正しい: OnionAwareDhtExecutor 経由でのみ呼ぶ
dht_executor.get(&mid).await?;
```

## テスト戦略

- `MockOnionAwareDhtExecutor` をテスト用に提供し、オニオン回路なしで DHT ロジックをテスト可能にする
- 本番実装 (`LiveOnionDhtExecutor`) はオニオン回路モジュールと統合テストで検証

## 実装順序の制約

**Month 4 の DHT 実装開始前に、このトレイト定義と `MockOnionAwareDhtExecutor` を完成させること。**
DHT の実装は常にこのトレイトに依存する形で書かれなければならない。
