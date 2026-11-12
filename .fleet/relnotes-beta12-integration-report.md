# beta.12 文書更新 — 統合報告(実物検証済み)

情報源: C:/work/wp-relnotes 作業ツリー(git_status / git_diff / git_log / read_file / grep / run_python で実物を検証)
検証日時: 2026-10-26(UTC)
ブランチ: docs/release-notes-beta12(main 追従、未コミット)

## 1. 担当範囲ごとの件数・完了・終端確認(実物で裏取り)

| # | 範囲 | 件数 | 完了 | 実物での終端確認 |
|---|---|---|---|---|
| 1 | RELEASE-NOTES.md 差し替え・旧版退避 | 差し替え1・退避2・URL1 | 済 | RELEASE-NOTES.md 1行目「# Miasma v0.3.2-beta.12」、末尾42行目に Releases リンク(github.com/MasayukiTa/miasma-protocol)。git_log(5641610/179f723/bf71459)と本文が整合 |
| 2 | RELEASE-NOTES.ja.md 新規・インストーラ同梱可否 | 新規1・同梱0 | 済 | ?? で新規実在。1行目「# Miasma 0.3.2-beta.12」。耐量子必須を日本語で記載 |
| 3 | README.md / README.ja.md | 確認2・修正0 | 済 | 両101行目に耐量子必須の説明を実在確認(README.md: 'requires a post-quantum hybrid ... by default'、README.ja.md: '既定で耐量子 hybrid が必須')。古い版表記なし |
| 4 | docs/variant-guide.md | 修正6 | 済 | 固定文字列 grep で6箇所が「Miasma v0.3.2-beta.12 (Beta)」形式・ハッシュなしを確認。0.3.1 残存なし |
| 5 | SECURITY.md | 確認1・修正0 | 済 | 5-7行目「the current version line is v0.3.2-beta.x」で beta.12 と整合。古い版の名指しなし |
| 6 | 残存版表記の全走査・文書修正 | 修正1 | 済 | web/pkg/package.json を 0.3.1→0.3.2 に修正。下記の追加検証で installer の beta.11 は例示表と判明 |

## 2. 未取得の範囲

欠落なし。6範囲すべて実物で終端確認済み。

## 3. 成果物ファイルパス(C:/work/wp-relnotes、未コミット)

変更・新規・退避:
- RELEASE-NOTES.md … beta.12 最終案へ全面差し替え+末尾に Releases リンク1行(M)
- RELEASE-NOTES.ja.md … 日本語版を新規追加(??)
- docs/variant-guide.md … 版表記6箇所を修正(M)
- web/pkg/package.json … version 0.3.1→0.3.2(M)
- docs/release-notes-archive/v0.3.1-beta.1.md … 旧 RELEASE-NOTES.md を退避(??、消さず保存)
- docs/release-notes-archive/v0.2.0-beta.1.md … 旧 RELEASE-NOTES-v0.2.0-beta.1.md を退避(??、削除元と内容一致を run_python で確認)
- RELEASE-NOTES-v0.2.0-beta.1.md … 退避に伴いリポジトリ直下から削除(D)

確認のみ・修正なし: README.md / README.ja.md / SECURITY.md

## 4. 必須項目への回答

- README 更新忘れ防止(オーナー最重要): README.md / README.ja.md を確認。ダウンロード例・SHA256例とも 0.3.2-beta.12 に一致、古い版表記なし。耐量子必須の説明を両版の101行目に実在確認。差し替え漏れなし。
- RELEASE-NOTES.md 差し替え: 済。古い v0.3.1-beta.1 は docs/release-notes-archive/ に退避(消さず)。末尾に Releases ページへのリンク1行を追加。
- RELEASE-NOTES.ja.md: リポジトリ直下に新規追加。インストーラは英語一本(installer/miasma.wxs の Docs は RELEASE-NOTES.md のみ、UI Language=1033)のため日本語版の同梱定義は追加せず(指示「不要なら足さない」に準拠)。
- variant-guide.md: タイトルを「Miasma v0.3.2-beta.12 (Beta)」形式・ハッシュなしに統一。「Technical Beta」→「Beta」。
- SECURITY.md: 「v0.3.2-beta.x」系列表記で beta.12 と整合、修正不要。
- 残存版表記の全走査: 文書系に古い版の残存なし。web/pkg/package.json のみ 0.3.2 へ修正。

## 5. 追加で見つかった点(本統合での再検証)

- installer/RELEASE_NOTES_WINDOWS.md:55 の `0.3.2-beta.11`: バージョン→MSI番号の変換規則を示す例示表の一行(beta.11/12/13/rc.1/final/次シリーズを並べ昇順ソートを説明)。古い版の名指しではなく、修正不要。変更すると規則説明が壊れる。
- 初回の正規表現 grep が偽陰性を返した(`\.` エスケープで no matches)。固定文字列 grep で再走査し、上記の実在・残存を確定した。
