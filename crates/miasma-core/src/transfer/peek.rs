//! Looking up the sender's file name before the receive starts, so a front end
//! can pre-fill its Save-As dialog.
//!
//! The peek reads the signed record and its manifest from the same sources a
//! real receive uses (`--via`, iroh, then the DHT; see
//! [`jobs::direct_sources`](super::jobs::direct_sources)) and nothing else: no
//! piece is fetched, no journal or output file is written, nothing is logged.
//! A protected transfer's name is sealed under the password, so it is opened
//! with the password the person typed.
//!
//! It is a convenience, never a gate. Every failure (nothing reachable, a wrong
//! or missing password, no name carried, the time limit) is the same
//! `None`, so a wrong password cannot be told apart from "this transfer has no
//! name", and the real receive that follows reports the real error.

use std::{future::Future, path::Path, time::Duration};

use zeroize::Zeroizing;

use super::{
    direct::{fetch_record_direct, ViaConfig},
    jobs::direct_sources,
    manifest::sanitize_file_name,
    receive::carried_name,
    share_id::TransferId,
    FetchedRecord,
};
use crate::network::MiasmaCoordinator;

/// How long a peek may take altogether before the front end gives up and offers
/// the placeholder name.
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(8);

/// The sanitised original file name carried by the record that `fetch`
/// produces, within `limit`. `None` for every kind of failure, deliberately
/// without telling them apart.
pub async fn peek_name_with<F>(
    fetch: F,
    password: Option<&Zeroizing<String>>,
    limit: Duration,
) -> Option<String>
where
    F: Future<Output = Option<FetchedRecord>>,
{
    let work = async {
        let fetched = fetch.await?;
        let v3_view = fetched.manifest_v4.as_ref().map(|m| m.as_v3_view());
        let name_manifest = fetched.manifest.as_ref().or(v3_view.as_ref());
        let name = carried_name(name_manifest, password).await.ok()??;
        sanitize_file_name(&name)
    };
    tokio::time::timeout(limit, work).await.ok().flatten()
}

/// The production peek for `target`: the direct sources in the receive's order,
/// then the DHT, all under [`PEEK_TIMEOUT`]. Dropping the future (or the time
/// limit) stops every lookup.
pub async fn peek_receive_name(
    coord: &MiasmaCoordinator,
    data_dir: &Path,
    target: &TransferId,
    password: Option<&Zeroizing<String>>,
    via: Option<ViaConfig>,
    iroh_ca_pem: Option<String>,
) -> Option<String> {
    let sources = direct_sources(data_dir, target, via, iroh_ca_pem);
    let mid = target.mid();
    let signer = target.share_id().map(|s| *s.publisher());
    let fetch = async {
        if sources.has_any() {
            if let Ok(found) = fetch_record_direct(&sources, target).await {
                return Some(found);
            }
        }
        coord.fetch_verified_record(&mid, signer).await.ok()
    };
    peek_name_with(fetch, password, PEEK_TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::hash::ContentId,
        network::types::DhtRecord,
        transfer::{PasswordProtection, Protection, TransferManifest},
        DissolutionParams,
    };

    const NAME: &str = "\u{65c5}\u{884c}\u{306e}\u{5199}\u{771f} final.png";

    fn params() -> DissolutionParams {
        DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        }
    }

    fn fetched(manifest: Option<TransferManifest>) -> FetchedRecord {
        FetchedRecord {
            record: DhtRecord {
                mid_digest: [7; 32],
                data_shards: 2,
                total_shards: 3,
                version: 1,
                locations: vec![],
                published_at: 1,
            },
            manifest,
            manifest_v4: None,
            signer: [9; 32],
        }
    }

    fn mid() -> ContentId {
        ContentId::from_digest([7; 32])
    }

    fn plain(name: Option<&str>) -> FetchedRecord {
        fetched(Some(
            TransferManifest::new(&mid(), [9; 32], params(), 1024, 10, Protection::None)
                .with_name(name),
        ))
    }

    /// A protected record carrying `NAME`, and the password it was sealed with.
    fn protected() -> (FetchedRecord, String) {
        let pw = format!("pw-1{:032x}", rand::random::<u128>());
        let (prot, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        let m = TransferManifest::new(
            &mid(),
            [9; 32],
            params(),
            1024,
            10,
            Protection::Password(prot),
        )
        .with_sealed_name(Some(NAME), &key);
        (fetched(Some(m)), pw)
    }

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    async fn peek(f: Option<FetchedRecord>, p: Option<&Zeroizing<String>>) -> Option<String> {
        peek_name_with(async { f }, p, Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn latest_manifest_returns_its_carried_name() {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let mut rec = plain(Some(NAME));
        let m = rec.manifest.take().unwrap();
        rec.manifest_v4 = Some(crate::transfer::ManifestV4 {
            version: crate::transfer::MANIFEST_VERSION_V4,
            mid: m.mid,
            publisher: key.verifying_key().to_bytes(),
            name: m.name,
            data_shards: m.data_shards,
            total_shards: m.total_shards,
            segment_size: m.segment_size,
            total_bytes: m.total_bytes,
            protection: m.protection,
            segments: m.segments,
            suite: crate::format::ObjectSuite::Suite2.id(),
            ext: Vec::new(),
        });
        assert_eq!(peek(Some(rec), None).await.as_deref(), Some(NAME));
    }

    #[tokio::test]
    async fn an_unprotected_name_is_returned_without_a_password() {
        assert_eq!(
            peek(Some(plain(Some(NAME))), None).await.as_deref(),
            Some(NAME)
        );
        // A password typed for a transfer that needs none changes nothing.
        let typed = pw("whatever-1!");
        assert_eq!(
            peek(Some(plain(Some(NAME))), Some(&typed)).await.as_deref(),
            Some(NAME)
        );
    }

    #[tokio::test]
    async fn a_protected_name_needs_the_right_password() {
        let (rec, right) = protected();
        assert_eq!(
            peek(Some(rec.clone_for_test()), Some(&pw(&right)))
                .await
                .as_deref(),
            Some(NAME)
        );
        // Wrong, missing: the same `None` as "no name", so nothing is revealed.
        let wrong = pw(&format!("pw-1{:032x}", rand::random::<u128>()));
        assert_eq!(peek(Some(rec.clone_for_test()), Some(&wrong)).await, None);
        assert_eq!(peek(Some(rec.clone_for_test()), None).await, None);
        assert_eq!(peek(Some(plain(None)), None).await, None);
    }

    #[tokio::test]
    async fn a_hostile_name_is_sanitised_and_an_unusable_one_is_none() {
        // The manifest is untrusted: path parts are dropped (here by the
        // carried-name path, which sanitises again).
        let mut rec = plain(Some("photo.png"));
        rec.manifest.as_mut().unwrap().name = Some("../../evil/ph\u{202e}oto.png".into());
        assert_eq!(peek(Some(rec), None).await.as_deref(), Some("photo.png"));
        let mut rec = plain(Some("photo.png"));
        rec.manifest.as_mut().unwrap().name = Some("CON".into());
        assert_eq!(peek(Some(rec), None).await, None);
        // A legacy record has no manifest at all.
        assert_eq!(peek(Some(fetched(None)), None).await, None);
    }

    #[tokio::test]
    async fn an_unreachable_source_and_a_timeout_both_give_none() {
        assert_eq!(peek(None, None).await, None);
        let slow = async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(plain(Some(NAME)))
        };
        let started = std::time::Instant::now();
        assert_eq!(
            peek_name_with(slow, None, Duration::from_millis(50)).await,
            None
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    impl FetchedRecord {
        fn clone_for_test(&self) -> FetchedRecord {
            FetchedRecord {
                record: self.record.clone(),
                manifest: self.manifest.clone(),
                manifest_v4: self.manifest_v4.clone(),
                signer: self.signer,
            }
        }
    }
}
