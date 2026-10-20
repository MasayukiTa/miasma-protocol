//! `miasma update check|apply|status`: look for, install and inspect updates.
//!
//! The commands only use the updater in `miasma_core::update`; the network is
//! contacted by `check` and `apply` and by nothing else, and not at all when
//! `update.mode` is `off`.
//!
//! Exit codes (so scripts can tell the answers apart):
//!
//! | code | meaning                                                         |
//! |------|-----------------------------------------------------------------|
//! |  0   | nothing newer (`check`), installed (`apply`), shown (`status`)  |
//! | 10   | a newer build is available (`check`)                            |
//! | 11   | a newer release exists but cannot be installed here             |
//! | 20   | the check failed (offline, rate limit, bad answer): *not* "none" |
//! | 30   | updates are switched off (`update.mode = off`)                  |
//! | 40   | not now: a transfer, push or chat send is running               |
//! | 41   | refused: the download did not verify                            |
//! | 42   | installed but the new version did not start; the old one is back |
//! | 43   | this installation cannot be updated in place                    |
//! | 44   | any other error while fetching or installing                    |

use std::path::Path;

use anyhow::{Context, Result};
use clap::Subcommand;
use miasma_core::{
    config::NodeConfig,
    update::{
        apply::{load_journal, Resumed},
        verify::UPDATE_PUBKEYS,
        CheckOutcome, Engine, Source, UpdateError, UpdateOffer,
    },
};

use crate::i18n::{lang, Lang};

pub const EXIT_NONE: i32 = 0;
pub const EXIT_AVAILABLE: i32 = 10;
pub const EXIT_NOT_INSTALLABLE: i32 = 11;
pub const EXIT_FAILED: i32 = 20;
pub const EXIT_DISABLED: i32 = 30;
pub const EXIT_BUSY: i32 = 40;
pub const EXIT_REFUSED: i32 = 41;
pub const EXIT_ROLLED_BACK: i32 = 42;
pub const EXIT_NO_TARGET: i32 = 43;
pub const EXIT_ERROR: i32 = 44;

#[derive(Subcommand)]
pub enum UpdateCmd {
    /// Look for a newer build. Prints `available`, `none` or `failed`; the exit
    /// code tells them apart (0 none, 10 available, 20 failed, 30 off).
    Check,
    /// Download, verify and install the newer build. Nothing is installed while
    /// a transfer, push or chat send is running. The previous version is kept
    /// as `<program>.prev`.
    Apply,
    /// Show the update settings, the running build and any update in progress.
    Status,
}

fn ja() -> bool {
    lang() == Lang::Ja
}

fn say(en: &str, jp: &str) {
    println!("{}", if ja() { jp } else { en });
}

fn engine(data_dir: &Path) -> Result<Engine> {
    let node = NodeConfig::load(data_dir).context("cannot load config")?;
    // The same extra CA the relay connections trust, for the GitHub requests.
    let ca_file = node.transport.iroh_extra_ca_pem.clone();
    Engine::new(
        data_dir,
        node.update,
        env!("MIASMA_VERSION"),
        env!("MIASMA_BUILD_ID"),
    )
    .map(|e| e.with_extra_ca_file(ca_file))
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Run on a thread that may block (the updater does its own network I/O).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow::anyhow!("worker failed: {e}"))
}

pub async fn run(data_dir: &Path, cmd: UpdateCmd) -> Result<i32> {
    match cmd {
        UpdateCmd::Check => check(data_dir).await,
        UpdateCmd::Apply => apply(data_dir).await,
        UpdateCmd::Status => status(data_dir).await,
    }
}

fn describe_offer(o: &UpdateOffer) {
    match o.source {
        Source::Release => say(
            &format!("available: version {} (GitHub release)", o.version),
            &format!("利用可能: バージョン {} (GitHub リリース)", o.version),
        ),
        Source::Local => say(
            &format!("available: local build {}", o.version),
            &format!("利用可能: ローカルビルド {}", o.version),
        ),
    }
    if o.skipped {
        say(
            "(you chose to skip this version)",
            "(このバージョンはスキップに設定されています)",
        );
    }
}

/// Print the answer of a check and return its exit code.
fn report(out: &CheckOutcome) -> i32 {
    match out {
        CheckOutcome::Disabled => {
            say(
                "disabled: updates are off (set update.mode to notify or auto)",
                "無効: 更新は off です (update.mode を notify か auto にしてください)",
            );
            EXIT_DISABLED
        }
        CheckOutcome::StoreManaged => {
            say(
                "store: updates are handled by the Microsoft Store",
                "ストア: 更新は Microsoft Store が行います",
            );
            EXIT_DISABLED
        }
        CheckOutcome::UpToDate { latest } => {
            match latest {
                Some(v) => say(
                    &format!("none: this is the newest build (newest release seen: {v})"),
                    &format!("なし: 最新です (確認した最新リリース: {v})"),
                ),
                None => say(
                    "none: no release is newer",
                    "なし: より新しいリリースはありません",
                ),
            }
            EXIT_NONE
        }
        CheckOutcome::Available(o) => {
            describe_offer(o);
            EXIT_AVAILABLE
        }
        CheckOutcome::NoAsset { version } => {
            say(
                &format!("available but not installable: release {version} has no file for this platform"),
                &format!("利用不可: リリース {version} にはこの環境向けのファイルがありません"),
            );
            EXIT_NOT_INSTALLABLE
        }
        CheckOutcome::Unverifiable { version } => {
            say(
                &format!("available but refused: release {version} has no SHA256SUMS.txt"),
                &format!("拒否: リリース {version} には SHA256SUMS.txt がありません"),
            );
            EXIT_NOT_INSTALLABLE
        }
        CheckOutcome::Failed(f) => {
            // Not "none": the answer is unknown.
            say(
                &format!("failed: could not check ({f}); this does not mean you are up to date"),
                &format!("失敗: 確認できませんでした ({f})。最新であるという意味ではありません"),
            );
            EXIT_FAILED
        }
    }
}

async fn check(data_dir: &Path) -> Result<i32> {
    let e = engine(data_dir)?;
    let out = blocking(move || e.check()).await?;
    Ok(report(&out))
}

fn error_code(e: &UpdateError) -> i32 {
    match e {
        UpdateError::Disabled | UpdateError::StoreManaged => EXIT_DISABLED,
        UpdateError::Busy(_) => EXIT_BUSY,
        UpdateError::Verify(_) | UpdateError::Unverifiable | UpdateError::Archive(_) => {
            EXIT_REFUSED
        }
        UpdateError::HealthCheck(_) => EXIT_ROLLED_BACK,
        UpdateError::NoTarget(_) | UpdateError::NotWritable(_) => EXIT_NO_TARGET,
        UpdateError::NoAsset => EXIT_NOT_INSTALLABLE,
        _ => EXIT_ERROR,
    }
}

async fn apply(data_dir: &Path) -> Result<i32> {
    let e = engine(data_dir)?;
    blocking(move || apply_blocking(e)).await?
}

fn apply_blocking(e: Engine) -> Result<i32> {
    // Finish or undo an update that an earlier run left half done.
    match e.resume() {
        Ok(Resumed::Completed(a)) => say(
            &format!("finished an interrupted update to {}", a.version),
            &format!("中断された更新を完了しました: {}", a.version),
        ),
        Ok(Resumed::RolledBack(why)) => say(
            &format!("an interrupted update was undone ({why})"),
            &format!("中断された更新を元に戻しました ({why})"),
        ),
        Ok(_) => {}
        Err(err) => {
            eprintln!("{err}");
            return Ok(error_code(&err));
        }
    }

    let out = e.check();
    let offer = match &out {
        CheckOutcome::Available(o) => o.clone(),
        other => return Ok(report(other)),
    };
    describe_offer(&offer);

    let mut last_pct = 0u64;
    let prepared = e.prepare(&offer, &mut |done, total| {
        if let Some(t) = total.filter(|t| *t > 0) {
            let pct = done * 100 / t;
            if pct >= last_pct + 10 || pct == 100 {
                last_pct = pct;
                eprintln!("  {pct}%");
            }
        }
    });
    let mut journal = match prepared {
        Ok(j) => j,
        Err(err) => {
            eprintln!("{err}");
            return Ok(error_code(&err));
        }
    };
    say(
        "downloaded and verified",
        "ダウンロードと検証が完了しました",
    );

    match e.apply(&mut journal) {
        Ok(done) => {
            say(
                &format!(
                    "installed {}. Restart Miasma (the window and the background service) to use it. The previous version is kept as <program>.prev",
                    done.version
                ),
                &format!(
                    "{} をインストールしました。Miasma (ウィンドウとバックグラウンドサービス) を再起動してください。以前のバージョンは <program>.prev として残してあります",
                    done.version
                ),
            );
            Ok(EXIT_NONE)
        }
        Err(err) => {
            eprintln!("{err}");
            Ok(error_code(&err))
        }
    }
}

async fn status(data_dir: &Path) -> Result<i32> {
    let cfg = NodeConfig::load(data_dir)
        .context("cannot load config")?
        .update;
    println!("mode:            {}", cfg.mode);
    println!("channel:         {}", cfg.channel);
    println!("check_at_start:  {}", cfg.check_at_start);
    println!(
        "local_build_dir: {}",
        cfg.local_build_dir.as_deref().unwrap_or("")
    );
    println!(
        "running:         {} ({})",
        env!("MIASMA_VERSION"),
        env!("MIASMA_BUILD_ID")
    );
    if UPDATE_PUBKEYS.is_empty() {
        println!("signature:       not enforced (no public key is pinned in this build); SHA256SUMS.txt is required; mode auto does not install by itself");
    } else {
        println!(
            "signature:       required ({} pinned key(s)); SHA256SUMS.txt is required",
            UPDATE_PUBKEYS.len()
        );
    }
    let state = miasma_core::update::state::UpdateState::load(data_dir);
    if let Some(v) = state.skipped_version {
        println!("skipped:         {v}");
    }
    let journal = miasma_core::update::engine::running_install_dir()
        .and_then(|dir| load_journal(data_dir, &dir));
    match journal {
        Ok(Some(j)) => println!("in progress:     {} ({:?})", j.version, j.phase),
        Ok(None) => println!("in progress:     none"),
        Err(e) => println!("in progress:     unreadable ({e})"),
    }
    Ok(EXIT_NONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::update::CheckFailure;

    #[test]
    fn the_answers_have_distinct_exit_codes() {
        let none = report(&CheckOutcome::UpToDate { latest: None });
        let avail = report(&CheckOutcome::Available(UpdateOffer {
            source: Source::Release,
            version: "9.9.9".into(),
            build_id: None,
            release: None,
            local_dir: None,
            skipped: false,
        }));
        let failed = report(&CheckOutcome::Failed(CheckFailure::Offline));
        let off = report(&CheckOutcome::Disabled);
        let mut codes = [none, avail, failed, off];
        assert_eq!(
            codes,
            [EXIT_NONE, EXIT_AVAILABLE, EXIT_FAILED, EXIT_DISABLED]
        );
        codes.sort();
        codes.windows(2).for_each(|w| assert_ne!(w[0], w[1]));
        // A failed check is never reported with the code of "none".
        assert_ne!(failed, none);
    }

    #[test]
    fn errors_map_to_their_own_codes() {
        assert_eq!(error_code(&UpdateError::Busy("x".into())), EXIT_BUSY);
        assert_eq!(error_code(&UpdateError::Unverifiable), EXIT_REFUSED);
        assert_eq!(
            error_code(&UpdateError::HealthCheck("x".into())),
            EXIT_ROLLED_BACK
        );
        assert_eq!(
            error_code(&UpdateError::NoTarget("x".into())),
            EXIT_NO_TARGET
        );
        assert_eq!(error_code(&UpdateError::Disabled), EXIT_DISABLED);
    }
}
