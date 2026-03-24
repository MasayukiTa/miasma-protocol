/// Transport diagnostics — fallback ladder tracing and diagnostic export.
///
/// Records the full fallback sequence for transport operations:
/// which transport was tried, in what order, what failed, what succeeded,
/// and wall time per step.
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::payload::{PayloadTransportKind, TransportAttempt};

// ─── Fallback ladder trace ──────────────────────────────────────────────────

/// A single transport step within a fallback sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackStep {
    /// Which transport was tried.
    pub transport: String,
    /// Whether it succeeded.
    pub succeeded: bool,
    /// Phase where it failed (if failed).
    pub phase: Option<String>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Wall time for this step.
    pub duration_ms: u64,
}

impl From<&TransportAttempt> for FallbackStep {
    fn from(a: &TransportAttempt) -> Self {
        Self {
            transport: a.transport.to_string(),
            succeeded: a.succeeded,
            phase: if a.succeeded {
                None
            } else {
                Some(a.phase.to_string())
            },
            error: a.error.clone(),
            duration_ms: a.duration.as_millis() as u64,
        }
    }
}

/// A complete fallback ladder trace for one operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackTrace {
    /// Unix timestamp (seconds) when the operation started.
    pub timestamp: u64,
    /// What operation was being performed.
    pub operation: String,
    /// Target peer/address.
    pub target: String,
    /// Ordered steps tried.
    pub steps: Vec<FallbackStep>,
    /// Which transport ultimately succeeded (if any).
    pub succeeded_transport: Option<String>,
    /// Total wall time for the entire fallback sequence.
    pub total_duration_ms: u64,
}

impl fmt::Display for FallbackTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match &self.succeeded_transport {
            Some(t) => format!("OK via {t}"),
            None => "FAILED (all transports exhausted)".to_string(),
        };
        write!(
            f,
            "[{}] {} → {} ({} steps, {}ms): {}",
            self.timestamp,
            self.operation,
            self.target,
            self.steps.len(),
            self.total_duration_ms,
            status
        )?;
        for (i, step) in self.steps.iter().enumerate() {
            if step.succeeded {
                write!(f, "\n  {}. {} → OK ({}ms)", i + 1, step.transport, step.duration_ms)?;
            } else {
                write!(
                    f,
                    "\n  {}. {} → FAIL at {} — {} ({}ms)",
                    i + 1,
                    step.transport,
                    step.phase.as_deref().unwrap_or("?"),
                    step.error.as_deref().unwrap_or("unknown"),
                    step.duration_ms
                )?;
            }
        }
        Ok(())
    }
}

// ─── Trace buffer ───────────────────────────────────────────────────────────

/// Thread-safe circular buffer of fallback traces for diagnostics.
pub struct FallbackTraceBuffer {
    traces: Mutex<VecDeque<FallbackTrace>>,
    capacity: usize,
}

impl FallbackTraceBuffer {
    /// Create a new trace buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            traces: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Record a fallback trace from transport attempts.
    pub fn record(
        &self,
        operation: &str,
        target: &str,
        attempts: &[TransportAttempt],
        succeeded_transport: Option<PayloadTransportKind>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let steps: Vec<FallbackStep> = attempts.iter().map(FallbackStep::from).collect();
        let total_ms: u64 = steps.iter().map(|s| s.duration_ms).sum();

        let trace = FallbackTrace {
            timestamp: now,
            operation: operation.to_string(),
            target: target.to_string(),
            steps,
            succeeded_transport: succeeded_transport.map(|t| t.to_string()),
            total_duration_ms: total_ms,
        };

        let mut buf = self.traces.lock().unwrap();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(trace);
    }

    /// Get all traces as a snapshot (newest last).
    pub fn snapshot(&self) -> Vec<FallbackTrace> {
        self.traces.lock().unwrap().iter().cloned().collect()
    }

    /// Get the most recent N traces.
    pub fn recent(&self, n: usize) -> Vec<FallbackTrace> {
        let buf = self.traces.lock().unwrap();
        buf.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect()
    }

    /// Number of traces currently stored.
    pub fn len(&self) -> usize {
        self.traces.lock().unwrap().len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.traces.lock().unwrap().is_empty()
    }

    /// Clear all traces.
    pub fn clear(&self) {
        self.traces.lock().unwrap().clear();
    }
}

impl Default for FallbackTraceBuffer {
    fn default() -> Self {
        Self::new(100)
    }
}

impl fmt::Debug for FallbackTraceBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.len();
        f.debug_struct("FallbackTraceBuffer")
            .field("len", &len)
            .field("capacity", &self.capacity)
            .finish()
    }
}

// ─── Diagnostics export ─────────────────────────────────────────────────────

/// Comprehensive transport diagnostics for CLI/HTTP export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportDiagnostics {
    /// Current fallback ladder (ordered transport names).
    pub fallback_ladder: Vec<String>,
    /// Per-transport success/failure counts.
    pub transport_stats: Vec<TransportStatEntry>,
    /// Recent fallback traces.
    pub recent_traces: Vec<FallbackTrace>,
    /// Whether the system is currently in fallback mode.
    pub in_fallback_mode: bool,
    /// The currently active (most recently successful) transport.
    pub active_transport: Option<String>,
}

/// Per-transport statistics for the diagnostics export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStatEntry {
    pub transport: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub session_failures: u64,
    pub data_failures: u64,
    pub last_error: Option<String>,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::payload::TransportPhase;
    use std::time::Duration;

    fn make_attempt(kind: PayloadTransportKind, success: bool) -> TransportAttempt {
        TransportAttempt {
            transport: kind,
            succeeded: success,
            phase: if success {
                TransportPhase::Data
            } else {
                TransportPhase::Session
            },
            error: if success {
                None
            } else {
                Some("test error".into())
            },
            duration: Duration::from_millis(100),
        }
    }

    #[test]
    fn trace_buffer_capacity() {
        let buf = FallbackTraceBuffer::new(3);
        for i in 0..5 {
            buf.record(
                "fetch",
                &format!("target-{i}"),
                &[make_attempt(PayloadTransportKind::DirectLibp2p, true)],
                Some(PayloadTransportKind::DirectLibp2p),
            );
        }
        assert_eq!(buf.len(), 3);
        let snap = buf.snapshot();
        // Oldest 2 evicted, remaining are targets 2, 3, 4
        assert_eq!(snap[0].target, "target-2");
        assert_eq!(snap[2].target, "target-4");
    }

    #[test]
    fn trace_buffer_recent() {
        let buf = FallbackTraceBuffer::new(10);
        for i in 0..5 {
            buf.record(
                "fetch",
                &format!("t-{i}"),
                &[make_attempt(PayloadTransportKind::DirectLibp2p, true)],
                Some(PayloadTransportKind::DirectLibp2p),
            );
        }
        let recent = buf.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].target, "t-3");
        assert_eq!(recent[1].target, "t-4");
    }

    #[test]
    fn fallback_step_from_attempt() {
        let attempt = make_attempt(PayloadTransportKind::WssTunnel, false);
        let step = FallbackStep::from(&attempt);
        assert_eq!(step.transport, "wss-tunnel");
        assert!(!step.succeeded);
        assert_eq!(step.phase, Some("session".to_string()));
        assert_eq!(step.error, Some("test error".to_string()));
    }

    #[test]
    fn fallback_trace_display() {
        let trace = FallbackTrace {
            timestamp: 1711234567,
            operation: "fetch_share".to_string(),
            target: "peer-abc".to_string(),
            steps: vec![
                FallbackStep {
                    transport: "direct-libp2p".to_string(),
                    succeeded: false,
                    phase: Some("session".to_string()),
                    error: Some("QUIC blocked".to_string()),
                    duration_ms: 5000,
                },
                FallbackStep {
                    transport: "tcp-direct".to_string(),
                    succeeded: true,
                    phase: None,
                    error: None,
                    duration_ms: 200,
                },
            ],
            succeeded_transport: Some("tcp-direct".to_string()),
            total_duration_ms: 5200,
        };
        let s = trace.to_string();
        assert!(s.contains("fetch_share"));
        assert!(s.contains("peer-abc"));
        assert!(s.contains("OK via tcp-direct"));
        assert!(s.contains("QUIC blocked"));
    }

    #[test]
    fn trace_record_with_failure() {
        let buf = FallbackTraceBuffer::new(10);
        let attempts = vec![
            make_attempt(PayloadTransportKind::DirectLibp2p, false),
            make_attempt(PayloadTransportKind::TcpDirect, false),
        ];
        buf.record("fetch", "target", &attempts, None);
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].succeeded_transport.is_none());
        assert_eq!(snap[0].steps.len(), 2);
    }

    #[test]
    fn diagnostics_serialization() {
        let diag = TransportDiagnostics {
            fallback_ladder: vec![
                "direct-libp2p".to_string(),
                "tcp-direct".to_string(),
                "wss-tunnel".to_string(),
            ],
            transport_stats: vec![TransportStatEntry {
                transport: "direct-libp2p".to_string(),
                success_count: 42,
                failure_count: 3,
                session_failures: 2,
                data_failures: 1,
                last_error: Some("timeout".to_string()),
            }],
            recent_traces: vec![],
            in_fallback_mode: false,
            active_transport: Some("direct-libp2p".to_string()),
        };
        let json = serde_json::to_string(&diag).unwrap();
        let deserialized: TransportDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fallback_ladder.len(), 3);
        assert_eq!(deserialized.transport_stats[0].success_count, 42);
    }

    #[test]
    fn trace_buffer_clear() {
        let buf = FallbackTraceBuffer::new(10);
        buf.record(
            "fetch",
            "target",
            &[make_attempt(PayloadTransportKind::DirectLibp2p, true)],
            Some(PayloadTransportKind::DirectLibp2p),
        );
        assert_eq!(buf.len(), 1);
        buf.clear();
        assert!(buf.is_empty());
    }
}
