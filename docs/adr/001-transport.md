# ADR-001: トランスポート層選定

**ステータス**: 決定済み
**日付**: 2026-03-16
**決定者**: プロジェクト初期設計

---

## コンテキスト

Miasma はモバイルファーストの P2P プロトコルであり、トランスポート層として以下2択を検討した。

| 選択肢 | 概要 |
|--------|------|
| A: `libp2p-quic` に一本化 | libp2p フレームワーク内蔵の QUIC transport を使用。接続管理・DHT・NAT traversal・Noise XX がフレームワークに統合されている。 |
| B: `quinn` + `rustls` 独自スタック | QUIC の低レイヤー制御が可能。接続管理・NAT traversal・ピア発見は全て自前実装が必要。 |

## 決定

**Option A: `libp2p-quic` に一本化する。**

接続管理は **libp2p connection manager のみ** とし、`quinn` 接続との併存は行わない。

## 根拠

1. **モバイル優先**: libp2p は Android/iOS 向け Rust ターゲットで実績があり、`rust-libp2p` の UniFFI ブリッジへの適合が容易。
2. **統合コスト削減**: Kademlia DHT・Noise XX・QUIC hole-punching・relay が `rust-libp2p` に同梱されており、Phase 1 MVP の工数を大幅に削減できる。
3. **NAT traversal**: `libp2p-relay` + QUIC hole-punching により、モバイルの NAT 越えを追加実装なしで対応可能。
4. **Sybil 耐性 DHT への拡張性**: Phase 3 の S/Kademlia は `rust-libp2p` の DHT 拡張として実装しやすい。

## トレードオフ（受け入れた制約）

- libp2p の connection manager に依存するため、超低レベルの QUIC 制御（例: connection migration の詳細制御）は制限される。
- libp2p のアップストリームバージョンに追従するメンテナンスコストが発生する。

## 実装方針

```toml
# Cargo.toml (miasma-core)
libp2p = { version = "0.54", features = ["quic", "kad", "noise", "yamux", "relay", "identify", "ping"] }
```

- トランスポート生成: `libp2p::quic::tokio::Transport`
- 暗号化: Noise XX (`libp2p-noise`)
- ストリーム多重化: Yamux
- DHT: `libp2p-kad` (Kademlia) — **ADR-002 の onion-aware API 境界を通じてのみ呼び出す**
