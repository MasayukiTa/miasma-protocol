use std::{collections::HashSet, future::Future, pin::Pin, time::Duration};

use futures::{stream::FuturesUnordered, StreamExt};

use crate::{
    crypto::hash::ContentId,
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

use super::source::ShareSource;

/// How aggressively retrieval may overlap holder fetches.
///
/// `Sequential` preserves the original one-request-at-a-time privacy behavior.
/// `Hedged` starts one request, waits `delay`, then launches at most one
/// secondary request if the first is still pending. As soon as k distinct valid
/// shares are collected, all remaining futures are dropped/cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchPolicy {
    Sequential,
    Hedged { delay: Duration },
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self::Sequential
    }
}

impl FetchPolicy {
    /// Conservative direct-network policy: only one secondary holder is raced,
    /// and only after the primary has been slow for 250 ms.
    pub fn direct_network() -> Self {
        Self::Hedged {
            delay: Duration::from_millis(250),
        }
    }
}

type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<MiasmaShare>, MiasmaError>> + Send + 'a>>;

fn fetch_future<'a, Src: ShareSource + ?Sized>(source: &'a Src, addr: String) -> FetchFuture<'a> {
    Box::pin(async move { source.fetch(&addr).await })
}

fn accept_share(
    result: Result<Option<MiasmaShare>, MiasmaError>,
    mid: &ContentId,
    segment_index: u32,
    seen_slots: &mut HashSet<u16>,
    valid: &mut Vec<MiasmaShare>,
) -> Result<(), MiasmaError> {
    match result? {
        Some(share)
            if share.segment_index == segment_index
                && ShareVerification::coarse_verify(&share, mid)
                && seen_slots.insert(share.slot_index) =>
        {
            valid.push(share);
        }
        _ => {}
    }
    Ok(())
}

/// Collect k distinct, coarse-verified shares from an already-shuffled candidate
/// list using the requested overlap policy.
///
/// The hedged path never has more than two holder fetches in flight. A second
/// request is launched only when the first has not completed before `delay`.
/// This bounds duplicate traffic while avoiding a single slow/dead holder from
/// serially stalling retrieval. Duplicate replicas of the same slot do not count
/// toward k.
pub(crate) async fn collect_verified_shares<'a, Src: ShareSource + ?Sized>(
    source: &'a Src,
    candidates: Vec<String>,
    mid: &ContentId,
    segment_index: u32,
    need: usize,
    policy: FetchPolicy,
) -> Result<Vec<MiasmaShare>, MiasmaError> {
    let mut valid = Vec::with_capacity(need);
    let mut seen_slots = HashSet::with_capacity(need);

    if need == 0 {
        return Ok(valid);
    }

    match policy {
        FetchPolicy::Sequential => {
            for addr in candidates {
                if valid.len() >= need {
                    break;
                }
                let result = source.fetch(&addr).await;
                accept_share(result, mid, segment_index, &mut seen_slots, &mut valid)?;
            }
        }
        FetchPolicy::Hedged { delay } => {
            let mut candidates = candidates.into_iter();
            let mut in_flight: FuturesUnordered<FetchFuture<'a>> = FuturesUnordered::new();

            let launch = |addr: String, in_flight: &mut FuturesUnordered<FetchFuture<'a>>| {
                in_flight.push(fetch_future(source, addr));
            };

            if let Some(addr) = candidates.next() {
                launch(addr, &mut in_flight);
            }

            while valid.len() < need && !in_flight.is_empty() {
                let result = if in_flight.len() == 1 {
                    match tokio::time::timeout(delay, in_flight.next()).await {
                        Ok(Some(result)) => Some(result),
                        Ok(None) => None,
                        Err(_) => {
                            if let Some(addr) = candidates.next() {
                                launch(addr, &mut in_flight);
                                continue;
                            }
                            in_flight.next().await
                        }
                    }
                } else {
                    in_flight.next().await
                };

                let Some(result) = result else {
                    break;
                };
                accept_share(result, mid, segment_index, &mut seen_slots, &mut valid)?;

                if valid.len() >= need {
                    break;
                }

                // If the completed request left no work in flight, start the next
                // primary immediately. If one hedge remains, let it run for the
                // configured delay before launching another secondary.
                if in_flight.is_empty() {
                    if let Some(addr) = candidates.next() {
                        launch(addr, &mut in_flight);
                    }
                }
            }
        }
    }

    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{dissolve, DissolutionParams};
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    #[derive(Clone)]
    struct DelaySource {
        entries: Arc<HashMap<String, (Duration, MiasmaShare)>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ShareSource for DelaySource {
        async fn list_candidates(&self, _mid: &ContentId) -> Vec<String> {
            self.entries.keys().cloned().collect()
        }

        async fn fetch(&self, address: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.entries.get(address) {
                Some((delay, share)) => {
                    tokio::time::sleep(*delay).await;
                    Ok(Some(share.clone()))
                }
                None => Ok(None),
            }
        }
    }

    fn source_fixture() -> (DelaySource, ContentId) {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"hedged retrieval fixture", params).unwrap();
        let entries = HashMap::from([
            (
                "slow".to_string(),
                (Duration::from_millis(200), shares[0].clone()),
            ),
            (
                "fast".to_string(),
                (Duration::from_millis(1), shares[1].clone()),
            ),
        ]);
        (
            DelaySource {
                entries: Arc::new(entries),
                calls: Arc::new(AtomicUsize::new(0)),
            },
            mid,
        )
    }

    #[tokio::test]
    async fn sequential_does_not_start_secondary_when_primary_is_enough() {
        let (source, mid) = source_fixture();
        let got = collect_verified_shares(
            &source,
            vec!["slow".into(), "fast".into()],
            &mid,
            0,
            1,
            FetchPolicy::Sequential,
        )
        .await
        .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].slot_index, 0);
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hedged_fetch_uses_fast_secondary_after_delay() {
        let (source, mid) = source_fixture();
        let got = collect_verified_shares(
            &source,
            vec!["slow".into(), "fast".into()],
            &mid,
            0,
            1,
            FetchPolicy::Hedged {
                delay: Duration::from_millis(10),
            },
        )
        .await
        .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].slot_index, 1);
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn duplicate_slot_replicas_do_not_satisfy_k() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"duplicate slot fixture", params).unwrap();
        let entries = HashMap::from([
            ("replica-a".to_string(), (Duration::ZERO, shares[0].clone())),
            ("replica-b".to_string(), (Duration::ZERO, shares[0].clone())),
            ("unique".to_string(), (Duration::ZERO, shares[1].clone())),
        ]);
        let source = DelaySource {
            entries: Arc::new(entries),
            calls: Arc::new(AtomicUsize::new(0)),
        };

        let got = collect_verified_shares(
            &source,
            vec!["replica-a".into(), "replica-b".into(), "unique".into()],
            &mid,
            0,
            2,
            FetchPolicy::Sequential,
        )
        .await
        .unwrap();

        assert_eq!(got.len(), 2);
        assert_eq!(source.calls.load(Ordering::SeqCst), 3);
        assert_ne!(got[0].slot_index, got[1].slot_index);
    }
}
