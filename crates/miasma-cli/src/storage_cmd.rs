//! `miasma storage ...`: list and delete the shares this node stores.
//!
//! When a daemon is running, both go through it (`ControlRequest::StorageList`
//! / `StorageDelete`) so the daemon's view of "in use" (pending replication and
//! active transfers) is respected. With no daemon, they work directly on the
//! encrypted share store on disk; nothing is then reported as in use.
//!
//! Messages follow the pattern of `chat_cmd.rs` (one `match` per language in one
//! enum, language from `i18n::lang()`).

use std::{
    io::Write as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use miasma_core::{
    config::NodeConfig,
    daemon_request,
    store::{DeleteSharesOutcome, LocalShareStore, ShareSelection, StoredShare},
    ControlRequest, ControlResponse,
};

use crate::i18n::{lang, Lang};

#[derive(Subcommand)]
pub enum StorageCmd {
    /// List the shares this node stores: short id, size, age and whether each is in use.
    List {
        /// Print one JSON object per share (for scripts).
        #[arg(long)]
        json: bool,
    },
    /// Delete shares this node stores. Shares in use (being replicated, or part of a running transfer) are left alone.
    Delete {
        /// Short ids from `miasma storage list` (or full addresses) to delete.
        #[arg(long = "id", value_name = "ID", num_args = 1..)]
        id: Vec<String>,
        /// Delete every stored share.
        #[arg(long)]
        all: bool,
        /// Delete shares whose data has not changed for this many days.
        #[arg(long, value_name = "DAYS")]
        older_than: Option<u64>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

// ─── Messages ────────────────────────────────────────────────────────────────

enum M<'a> {
    DaemonOld,
    NoShares,
    Header {
        count: usize,
        in_use: usize,
        total: &'a str,
    },
    Row {
        id: &'a str,
        size: &'a str,
        when: &'a str,
        in_use: bool,
    },
    NeedSelection,
    AmbiguousSelection,
    Confirm {
        count: usize,
        bytes: &'a str,
    },
    PromptYes,
    Aborted,
    NothingToDelete,
    Deleted {
        n: usize,
        freed: &'a str,
    },
    Skipped(&'a [String]),
}

impl M<'_> {
    fn t(&self) -> String {
        match lang() {
            Lang::En => self.en(),
            Lang::Ja => self.ja(),
        }
    }

    fn en(&self) -> String {
        match self {
            M::DaemonOld => "The running Miasma daemon is older than this command and does not support storage management. Restart it after updating.".into(),
            M::NoShares => "No stored shares.".into(),
            M::Header { count, in_use, total } => {
                format!("{count} share(s), {in_use} in use, {total} total.")
            }
            M::Row { id, size, when, in_use } => {
                let mark = if *in_use { "  (in use)" } else { "" };
                format!("{id}  {size}  {when}{mark}")
            }
            M::NeedSelection => "Name at least one share id, or use --all or --older-than DAYS.".into(),
            M::AmbiguousSelection => "Name the shares one way only: ids, or --all, or --older-than DAYS.".into(),
            M::Confirm { count, bytes } => format!(
                "This permanently deletes {count} share(s) ({bytes}) from this device. People who received a share ID for these files will no longer be able to download them."
            ),
            M::PromptYes => "Type 'yes' to continue: ".into(),
            M::Aborted => "Aborted; nothing was deleted.".into(),
            M::NothingToDelete => "Nothing to delete (no matching share, or all of them are in use).".into(),
            M::Deleted { n, freed } => format!("Deleted {n} share(s), freed {freed}."),
            M::Skipped(ids) => format!("Skipped (in use or unsafe): {}.", ids.join(", ")),
        }
    }

    fn ja(&self) -> String {
        match self {
            M::DaemonOld => "起動中のMiasmaデーモンが古く、ストレージ管理に対応していません。更新してから再起動してください。".into(),
            M::NoShares => "保存している共有はありません。".into(),
            M::Header { count, in_use, total } => {
                format!("共有 {count} 件、使用中 {in_use} 件、合計 {total}。")
            }
            M::Row { id, size, when, in_use } => {
                let mark = if *in_use { "  (使用中)" } else { "" };
                format!("{id}  {size}  {when}{mark}")
            }
            M::NeedSelection => "共有のIDを少なくとも1つ指定するか、--all または --older-than DAYS を使ってください。".into(),
            M::AmbiguousSelection => "指定方法は1つにしてください: ID、--all、--older-than DAYS のいずれか。".into(),
            M::Confirm { count, bytes } => format!(
                "この端末から共有 {count} 件({bytes})を完全に削除します。これらのファイルの共有IDを受け取った人は、もうダウンロードできなくなります。"
            ),
            M::PromptYes => "続けるには 'yes' と入力してください: ".into(),
            M::Aborted => "中止しました。何も削除していません。".into(),
            M::NothingToDelete => "削除するものはありません(該当する共有がないか、すべて使用中です)。".into(),
            M::Deleted { n, freed } => format!("共有 {n} 件を削除し、{freed} を解放しました。"),
            M::Skipped(ids) => format!("スキップ(使用中または安全でないため): {}。", ids.join(", ")),
        }
    }
}

/// `YYYY-MM-DD` in UTC for UNIX seconds.
fn date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Plumbing ────────────────────────────────────────────────────────────────

fn daemon_present(data_dir: &Path) -> bool {
    data_dir.join(miasma_core::daemon::ipc::PORT_FILE).exists()
}

fn open_store(data_dir: &Path) -> Result<LocalShareStore> {
    let config = NodeConfig::load(data_dir).unwrap_or_default();
    LocalShareStore::open(data_dir, config.storage.quota_mb).context("cannot open share store")
}

/// Current listing: from the daemon when one is running, else straight from the
/// store on disk.
async fn fetch_list(data_dir: &Path) -> Result<(Vec<StoredShare>, u64)> {
    if !daemon_present(data_dir) {
        let store = open_store(data_dir)?;
        let shares = store.list_shares();
        let total = shares.iter().map(|s| s.size_bytes).sum();
        return Ok((shares, total));
    }
    match daemon_request(data_dir, ControlRequest::StorageList).await {
        Ok(ControlResponse::StorageList {
            shares,
            total_bytes,
        }) => Ok((shares, total_bytes)),
        Ok(ControlResponse::Error(e)) => {
            tracing::debug!("daemon error: {e}");
            bail!("{}", M::DaemonOld.t())
        }
        Ok(other) => bail!("unexpected response: {other:?}"),
        Err(e) => Err(e),
    }
}

/// Whether a listed share matches the selection. Used only to size the
/// confirmation prompt; the daemon (or the store) is what actually deletes.
fn matches(share: &StoredShare, selection: &ShareSelection, now: u64) -> bool {
    match selection {
        ShareSelection::Ids(ids) => ids.iter().any(|id| {
            id.len() >= miasma_core::store::SHORT_ID_LEN && share.address.starts_with(id.as_str())
        }),
        ShareSelection::All => true,
        ShareSelection::OlderThanDays(days) => {
            share.modified_secs > 0
                && now.saturating_sub(share.modified_secs) >= days.saturating_mul(24 * 60 * 60)
        }
    }
}

fn confirm_yes() -> Result<bool> {
    print!("{}", M::PromptYes.t());
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("cannot read the confirmation")?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

// ─── Commands ────────────────────────────────────────────────────────────────

pub async fn run_storage(data_dir: &Path, cmd: StorageCmd) -> Result<()> {
    match cmd {
        StorageCmd::List { json } => cmd_list(data_dir, json).await,
        StorageCmd::Delete {
            id,
            all,
            older_than,
            yes,
        } => cmd_delete(data_dir, id, all, older_than, yes).await,
    }
}

async fn cmd_list(data_dir: &Path, json: bool) -> Result<()> {
    let (shares, total_bytes) = fetch_list(data_dir).await?;
    if json {
        for s in &shares {
            println!(
                "{}",
                serde_json::to_string(s).context("cannot render a share as JSON")?
            );
        }
        return Ok(());
    }
    if shares.is_empty() {
        println!("{}", M::NoShares.t());
        return Ok(());
    }
    let in_use = shares.iter().filter(|s| s.in_use).count();
    let total = crate::human_bytes(total_bytes);
    println!(
        "{}",
        M::Header {
            count: shares.len(),
            in_use,
            total: &total,
        }
        .t()
    );
    for s in &shares {
        let size = crate::human_bytes(s.size_bytes);
        let when = if s.modified_secs == 0 {
            "-".to_owned()
        } else {
            date(s.modified_secs)
        };
        println!(
            "{}",
            M::Row {
                id: &s.id,
                size: &size,
                when: &when,
                in_use: s.in_use,
            }
            .t()
        );
    }
    Ok(())
}

async fn cmd_delete(
    data_dir: &Path,
    ids: Vec<String>,
    all: bool,
    older_than: Option<u64>,
    yes: bool,
) -> Result<()> {
    let kinds = [!ids.is_empty(), all, older_than.is_some()]
        .into_iter()
        .filter(|k| *k)
        .count();
    if kinds == 0 {
        bail!("{}", M::NeedSelection.t());
    }
    if kinds > 1 {
        bail!("{}", M::AmbiguousSelection.t());
    }
    let selection = if all {
        ShareSelection::All
    } else if let Some(days) = older_than {
        ShareSelection::OlderThanDays(days)
    } else {
        ShareSelection::Ids(ids)
    };

    // Size the confirmation from the current listing. When there is no daemon,
    // nothing is known to be in use and the listing says so.
    let (shares, _total) = fetch_list(data_dir).await?;
    let now = now_secs();
    let matching: Vec<&StoredShare> = shares
        .iter()
        .filter(|s| matches(s, &selection, now))
        .collect();
    let deletable: Vec<&&StoredShare> = matching.iter().filter(|s| !s.in_use).collect();
    let bytes: u64 = deletable.iter().map(|s| s.size_bytes).sum();

    if deletable.is_empty() {
        println!("{}", M::NothingToDelete.t());
        return Ok(());
    }
    if !yes {
        let bytes = crate::human_bytes(bytes);
        println!(
            "{}",
            M::Confirm {
                count: deletable.len(),
                bytes: &bytes,
            }
            .t()
        );
        if !confirm_yes()? {
            bail!("{}", M::Aborted.t());
        }
    }

    let outcome: DeleteSharesOutcome = if daemon_present(data_dir) {
        match daemon_request(data_dir, ControlRequest::StorageDelete { selection }).await {
            Ok(ControlResponse::StorageDeleted {
                deleted,
                freed_bytes,
                skipped,
            }) => DeleteSharesOutcome {
                deleted,
                freed_bytes,
                skipped,
            },
            Ok(ControlResponse::Error(e)) => {
                tracing::debug!("daemon error: {e}");
                bail!("{}", M::DaemonOld.t())
            }
            Ok(other) => bail!("unexpected response: {other:?}"),
            Err(e) => return Err(e),
        }
    } else {
        let store = open_store(data_dir)?;
        store.delete_shares(&selection)?
    };

    let freed = crate::human_bytes(outcome.freed_bytes);
    println!(
        "{}",
        M::Deleted {
            n: outcome.deleted,
            freed: &freed,
        }
        .t()
    );
    if !outcome.skipped.is_empty() {
        println!("{}", M::Skipped(&outcome.skipped).t());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_days() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_700_000_000), "2023-11-14");
        assert_eq!(date(951_782_400), "2000-02-29");
    }

    #[test]
    fn every_message_renders_in_both_languages() {
        let skipped = vec!["deadbeef".to_string()];
        let all = [
            M::DaemonOld,
            M::NoShares,
            M::Header {
                count: 2,
                in_use: 1,
                total: "3.0 MiB",
            },
            M::Row {
                id: "deadbeef",
                size: "1.5 MiB",
                when: "2023-11-14",
                in_use: true,
            },
            M::Row {
                id: "cafebabe",
                size: "512 B",
                when: "-",
                in_use: false,
            },
            M::NeedSelection,
            M::AmbiguousSelection,
            M::Confirm {
                count: 3,
                bytes: "4.5 MiB",
            },
            M::PromptYes,
            M::Aborted,
            M::NothingToDelete,
            M::Deleted {
                n: 3,
                freed: "4.5 MiB",
            },
            M::Skipped(&skipped),
        ];
        for m in &all {
            assert!(!m.en().is_empty());
            assert!(!m.ja().is_empty());
        }
        assert!(M::Row {
            id: "deadbeef",
            size: "1.5 MiB",
            when: "2023-11-14",
            in_use: true,
        }
        .en()
        .contains("in use"));
        assert!(M::Deleted {
            n: 3,
            freed: "4.5 MiB"
        }
        .ja()
        .contains("3"));
        assert!(M::Confirm {
            count: 3,
            bytes: "4.5 MiB"
        }
        .en()
        .contains("no longer be able to download"));
    }

    fn share(id: &str, address: &str, size: u64, modified_secs: u64, in_use: bool) -> StoredShare {
        StoredShare {
            id: id.into(),
            address: address.into(),
            size_bytes: size,
            modified_secs,
            in_use,
        }
    }

    #[test]
    fn selection_matching_covers_ids_all_and_age() {
        let s = share("deadbeef", "deadbeefcafe", 10, 1_000, false);
        let now = 1_000 + 10 * 24 * 60 * 60;
        assert!(matches(&s, &ShareSelection::All, now));
        assert!(matches(
            &s,
            &ShareSelection::Ids(vec!["deadbeef".into()]),
            now
        ));
        assert!(matches(
            &s,
            &ShareSelection::Ids(vec!["deadbeefcafe".into()]),
            now
        ));
        assert!(!matches(
            &s,
            &ShareSelection::Ids(vec!["cafebabe".into()]),
            now
        ));
        assert!(matches(&s, &ShareSelection::OlderThanDays(5), now));
        assert!(!matches(&s, &ShareSelection::OlderThanDays(30), now));
    }
}
