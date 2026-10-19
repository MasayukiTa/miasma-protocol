use std::{collections::HashSet, future::Future, pin::Pin, time::Duration};

use futures::{stream::FuturesUnordered, StreamExt};

use crate::{
    crypto::hash::ContentId,
    network::AnonymityPolicy,
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

    /// Hedging policy for a retrieval under `anonymity`.
    ///
    /// A hedge sends a second request to another holder while the first is still
    /// outstanding. That is acceptable when the requester is not hiding its
    /// address (`Direct`). Under `Opportunistic` or `Required` anonymity the
    /// requests would be linkable by timing, and a hedge launched after a relay
    /// path stalled could also leave the path class the policy chose, so those
    /// retrievals stay sequential: one holder at a time, in shuffled order.
    pub fn for_anonymity(anonymity: AnonymityPolicy) -> Self {
        Self::direct_network().constrained_by(anonymity)
    }

    /// Clamp this policy to what `anonymity` allows: hedging is only permitted
    /// when the anonymity policy is `Direct`; every other policy forces
    /// `Sequential`.
    pub fn constrained_by(self, anonymity: AnonymityPolicy) -> Self {
        match anonymity {
            AnonymityPolicy::Direct => self,
            AnonymityPolicy::Opportunistic | AnonymityPolicy::Required { .. } => Self::Sequential,
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

    // ── slow-holder / cancel cleanup / hedging policy ───────────────────────

    /// Decrements the in-flight counter when the fetch future finishes or is
    /// dropped, so a cancelled fetch is visible as `in_flight == 0`.
    struct InFlightGuard(Arc<AtomicUsize>);

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct TrackedSource {
        entries: Arc<HashMap<String, (Duration, MiasmaShare)>>,
        started: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl TrackedSource {
        fn new(entries: Vec<(&str, Duration, MiasmaShare)>) -> Self {
            Self {
                entries: Arc::new(
                    entries
                        .into_iter()
                        .map(|(addr, delay, share)| (addr.to_string(), (delay, share)))
                        .collect(),
                ),
                started: Arc::new(AtomicUsize::new(0)),
                completed: Arc::new(AtomicUsize::new(0)),
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ShareSource for TrackedSource {
        async fn list_candidates(&self, _mid: &ContentId) -> Vec<String> {
            self.entries.keys().cloned().collect()
        }

        async fn fetch(&self, address: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let _guard = InFlightGuard(self.in_flight.clone());
            let Some((delay, share)) = self.entries.get(address) else {
                return Ok(None);
            };
            tokio::time::sleep(*delay).await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(Some(share.clone()))
        }
    }

    fn tracked_fixture(count: usize, delay: Duration) -> (TrackedSource, ContentId, Vec<String>) {
        let (mid, shares) = dissolve(b"slow holder fixture", DissolutionParams::default()).unwrap();
        assert!(shares.len() >= count, "fixture needs {count} shares");
        let names: Vec<String> = (0..count).map(|i| format!("holder-{i}")).collect();
        let entries = names
            .iter()
            .zip(shares)
            .map(|(name, share)| (name.as_str(), delay, share))
            .collect();
        (TrackedSource::new(entries), mid, names)
    }

    #[tokio::test(start_paused = true)]
    async fn hedged_fetch_cancels_the_slow_holder_once_enough_shares_arrive() {
        let (mid, shares) = dissolve(b"slow holder fixture", DissolutionParams::default()).unwrap();
        let source = TrackedSource::new(vec![
            ("slow", Duration::from_secs(60), shares[0].clone()),
            ("fast", Duration::from_millis(1), shares[1].clone()),
        ]);
        let began = tokio::time::Instant::now();
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
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "waited for the slow holder"
        );
        assert_eq!(source.started.load(Ordering::SeqCst), 2);
        assert_eq!(source.completed.load(Ordering::SeqCst), 1);
        assert_eq!(
            source.in_flight.load(Ordering::SeqCst),
            0,
            "slow holder's fetch was not cancelled"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hedged_fetch_never_has_more_than_two_requests_in_flight() {
        let (source, mid, names) = tracked_fixture(6, Duration::from_millis(100));
        let got = collect_verified_shares(
            &source,
            names,
            &mid,
            0,
            3,
            FetchPolicy::Hedged {
                delay: Duration::from_millis(10),
            },
        )
        .await
        .unwrap();

        assert_eq!(got.len(), 3);
        assert!(
            source.peak.load(Ordering::SeqCst) <= 2,
            "more than one secondary"
        );
        assert!(
            source.peak.load(Ordering::SeqCst) >= 2,
            "hedge never started"
        );
        assert_eq!(
            source.in_flight.load(Ordering::SeqCst),
            0,
            "leftover requests"
        );
        assert!(source.started.load(Ordering::SeqCst) < 6, "fetched past k");
    }

    #[tokio::test(start_paused = true)]
    async fn hedged_fetch_dropped_by_the_caller_leaves_nothing_in_flight() {
        let (source, mid, names) = tracked_fixture(4, Duration::from_secs(3_600));
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            collect_verified_shares(
                &source,
                names,
                &mid,
                0,
                2,
                FetchPolicy::Hedged {
                    delay: Duration::from_millis(10),
                },
            ),
        )
        .await;

        assert!(
            outcome.is_err(),
            "every holder is slow, the caller must time out"
        );
        assert!(
            source.started.load(Ordering::SeqCst) >= 2,
            "hedge never started"
        );
        assert_eq!(source.completed.load(Ordering::SeqCst), 0);
        assert_eq!(
            source.in_flight.load(Ordering::SeqCst),
            0,
            "cancelling the retrieval must drop every outstanding fetch"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hedged_fetch_with_a_single_slow_holder_waits_for_it() {
        let (source, mid, names) = tracked_fixture(1, Duration::from_millis(400));
        let got = collect_verified_shares(
            &source,
            names,
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
        assert_eq!(source.started.load(Ordering::SeqCst), 1);
        assert_eq!(source.in_flight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hedging_is_only_allowed_when_the_anonymity_policy_is_direct() {
        assert_eq!(
            FetchPolicy::for_anonymity(AnonymityPolicy::Direct),
            FetchPolicy::direct_network()
        );
        for policy in [
            AnonymityPolicy::Opportunistic,
            AnonymityPolicy::Required { min_hops: 1 },
            AnonymityPolicy::Required { min_hops: 3 },
        ] {
            assert_eq!(FetchPolicy::for_anonymity(policy), FetchPolicy::Sequential);
            assert_eq!(
                FetchPolicy::direct_network().constrained_by(policy),
                FetchPolicy::Sequential,
                "{policy} must clamp a hedged policy"
            );
        }
        let hedged = FetchPolicy::Hedged {
            delay: Duration::from_millis(5),
        };
        assert_eq!(hedged.constrained_by(AnonymityPolicy::Direct), hedged);
        assert_eq!(
            FetchPolicy::Sequential.constrained_by(AnonymityPolicy::Direct),
            FetchPolicy::Sequential
        );
    }

    #[tokio::test(start_paused = true)]
    async fn required_anonymity_never_overlaps_holder_requests() {
        let (source, mid, names) = tracked_fixture(5, Duration::from_millis(100));
        let policy = FetchPolicy::for_anonymity(AnonymityPolicy::Required { min_hops: 2 });
        let got = collect_verified_shares(&source, names, &mid, 0, 2, policy)
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            source.peak.load(Ordering::SeqCst),
            1,
            "a required-anonymity retrieval must not hedge"
        );
        assert_eq!(source.started.load(Ordering::SeqCst), 2);
    }
}
