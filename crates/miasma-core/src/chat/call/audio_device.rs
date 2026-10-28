//! Real capture and playback through the platform audio API, behind the
//! `call-audio` feature. This file is the only place that speaks to `cpal`.
//!
//! The media tick runs every 20 ms and wants mono PCM at the codec rate
//! ([`CODEC_SAMPLE_RATE`] = 48 kHz, [`SAMPLES_PER_FRAME`] = 960 samples per
//! frame). A device runs at its own rate on its own callback thread. Between
//! that thread and the tick sits a small lock-based ring buffer: the callback
//! never blocks; on the tick side an underrun plays silence and on the
//! callback side an overflow drops the oldest audio.
//!
//! Failure is graceful: with no device or a denied permission the constructor
//! returns a typed [`AudioDeviceError`] the controller can turn into a call
//! notice, and the call can still proceed receive-only (an input that yields
//! silence, an output that is simply absent).
//!
//! Privacy: audio samples are media content; no sample, key, nonce, call id or
//! peer id ever reaches a log, an error message or a `Debug` output. The
//! error type is a bare enum with fixed text and does not carry device
//! internals.

use super::codec::{CODEC_SAMPLE_RATE, SAMPLES_PER_FRAME};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// How many 20 ms frames of PCM the ring buffer may hold before the oldest is
/// dropped. Four frames (80 ms) absorbs normal callback jitter without adding
/// much latency.
const RING_FRAMES: usize = 4;
const RING_CAPACITY_SAMPLES: usize = RING_FRAMES * SAMPLES_PER_FRAME;

/// A typed audio-device failure. Fixed text only; no device name, no sample,
/// no key material. The controller turns this into a call notice.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AudioDeviceError {
    /// No default device of the requested kind exists.
    NoDevice,
    /// The OS refused access to the device (for example a denied microphone
    /// permission).
    PermissionDenied,
    /// The device exists but its configuration could not be used.
    Unsupported,
    /// The audio backend failed to build or start the stream.
    Backend,
}

// A bare `Debug` mirroring only the variant name, so `?` and asserts cannot
// leak a device identity.
impl core::fmt::Debug for AudioDeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AudioDeviceError::NoDevice => "NoDevice",
            AudioDeviceError::PermissionDenied => "PermissionDenied",
            AudioDeviceError::Unsupported => "Unsupported",
            AudioDeviceError::Backend => "Backend",
        })
    }
}

impl core::fmt::Display for AudioDeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AudioDeviceError::NoDevice => "no audio device is available",
            AudioDeviceError::PermissionDenied => "audio device access was denied",
            AudioDeviceError::Unsupported => "the audio device configuration is not supported",
            AudioDeviceError::Backend => "the audio backend failed",
        })
    }
}

impl std::error::Error for AudioDeviceError {}

/// Which device to pick: the host default, or a device chosen by name.
#[derive(Clone, Default)]
pub enum DeviceChoice {
    /// The host's default device for the direction.
    #[default]
    Default,
    /// A device whose reported name equals this string.
    ByName(String),
}

/// Lists the input and output devices the host reports, by name. No UI; this
/// is the data a UI or a config file would choose from.
pub struct AudioDeviceList;

impl AudioDeviceList {
    /// Names of available input devices. An empty vector means none were found
    /// or the host could not be queried.
    pub fn inputs() -> Vec<String> {
        Self::names(|host| host.input_devices())
    }
    /// Names of available output devices.
    pub fn outputs() -> Vec<String> {
        Self::names(|host| host.output_devices())
    }

    fn names<I>(list: impl Fn(&cpal::Host) -> Result<I, cpal::DevicesError>) -> Vec<String>
    where
        I: Iterator<Item = cpal::Device>,
    {
        let host = cpal::default_host();
        let mut names = Vec::new();
        if let Ok(devices) = list(&host) {
            for device in devices {
                if let Ok(name) = device.name() {
                    names.push(name);
                }
            }
        }
        names
    }
}

/// The audio devices the host reports, by name, plus the host default of each
/// direction. This is the plain data a UI or a config file chooses from; it
/// holds only device names (no handles), so it is `Send` and crosses between
/// the enumeration thread and the caller freely.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DeviceList {
    /// Names of the available input (capture) devices.
    pub inputs: Vec<String>,
    /// Names of the available output (playback) devices.
    pub outputs: Vec<String>,
    /// The host's default input device name, if there is one.
    pub default_input: Option<String>,
    /// The host's default output device name, if there is one.
    pub default_output: Option<String>,
}

/// Enumerate the host's audio devices and return their names and the default of
/// each direction.
///
/// The cpal host and device handles are not guaranteed to be `Send`, so the
/// enumeration runs on a short-lived thread and only plain `String`s come back.
/// Any failure (the host cannot be queried, the thread cannot be joined) yields
/// empty lists and `None` defaults rather than a panic, so a caller can always
/// show what it got.
pub fn list_devices() -> DeviceList {
    thread::Builder::new()
        .spawn(enumerate_devices)
        .ok()
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

/// The host enumeration proper, run on the short-lived thread. Every step is
/// fallible-tolerant: a device whose name cannot be read is skipped and a
/// missing default is simply `None`.
fn enumerate_devices() -> DeviceList {
    let host = cpal::default_host();
    let default_name = |device: Option<cpal::Device>| device.and_then(|d| d.name().ok());
    DeviceList {
        inputs: collect_names(host.input_devices()),
        outputs: collect_names(host.output_devices()),
        default_input: default_name(host.default_input_device()),
        default_output: default_name(host.default_output_device()),
    }
}

/// Collect the names of an iterator of devices, tolerant of failure: an error
/// enumerating the devices yields an empty list, and a device whose name
/// cannot be read is skipped. Generic over the iterator type so it accepts
/// whatever concrete iterator `host.input_devices()` / `host.output_devices()`
/// return on the current platform.
fn collect_names<I>(devices: Result<I, cpal::DevicesError>) -> Vec<String>
where
    I: Iterator<Item = cpal::Device>,
{
    let mut names = Vec::new();
    if let Ok(devices) = devices {
        for device in devices {
            if let Ok(name) = device.name() {
                names.push(name);
            }
        }
    }
    names
}

fn pick_input(host: &cpal::Host, choice: &DeviceChoice) -> Result<cpal::Device, AudioDeviceError> {
    match choice {
        DeviceChoice::Default => host
            .default_input_device()
            .ok_or(AudioDeviceError::NoDevice),
        DeviceChoice::ByName(name) => host
            .input_devices()
            .map_err(|_| AudioDeviceError::Backend)?
            .find(|d| d.name().map(|n| &n == name).unwrap_or(false))
            .ok_or(AudioDeviceError::NoDevice),
    }
}

fn pick_output(host: &cpal::Host, choice: &DeviceChoice) -> Result<cpal::Device, AudioDeviceError> {
    match choice {
        DeviceChoice::Default => host
            .default_output_device()
            .ok_or(AudioDeviceError::NoDevice),
        DeviceChoice::ByName(name) => host
            .output_devices()
            .map_err(|_| AudioDeviceError::Backend)?
            .find(|d| d.name().map(|n| &n == name).unwrap_or(false))
            .ok_or(AudioDeviceError::NoDevice),
    }
}

/// A bounded FIFO of PCM samples shared between a device callback thread and
/// the media tick. The callback never blocks: it takes the lock only briefly
/// and drops the oldest samples on overflow. The lock is held for a push or a
/// pop of at most a frame, so the callback thread is never parked on audio
/// work.
struct SampleRing {
    samples: Mutex<VecDeque<i16>>,
    capacity: usize,
}

impl SampleRing {
    fn new(capacity: usize) -> Self {
        Self {
            samples: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }
    /// Push samples, dropping the oldest when full. Returns how many were
    /// dropped so a caller can count overflow.
    fn push(&self, incoming: &[i16]) -> usize {
        let mut queue = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        let mut dropped = 0;
        for &sample in incoming {
            if queue.len() == self.capacity {
                queue.pop_front();
                dropped += 1;
            }
            queue.push_back(sample);
        }
        dropped
    }
    /// Fill `out` from the front; any shortfall is left as the silence the
    /// caller pre-filled. Returns how many real samples were taken.
    fn pop_into(&self, out: &mut [i16]) -> usize {
        let mut queue = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        let take = out.len().min(queue.len());
        for slot in out.iter_mut().take(take) {
            *slot = queue.pop_front().unwrap_or(0);
        }
        take
    }
    fn len(&self) -> usize {
        self.samples.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Down-mix interleaved frames to mono by averaging channels.
fn down_mix(input: &[f32], channels: usize, out: &mut Vec<i16>) {
    if channels <= 1 {
        out.extend(input.iter().map(|&s| to_i16(s)));
        return;
    }
    for frame in input.chunks(channels) {
        let sum: f32 = frame.iter().copied().sum();
        out.push(to_i16(sum / channels as f32));
    }
}

fn to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * i16::MAX as f32) as i16
}

fn to_f32(sample: i16) -> f32 {
    sample as f32 / i16::MAX as f32
}

/// Length of a linear resample of `in_len` samples from `from` Hz to `to` Hz.
/// Kept as its own function so the tick-side buffering and the test agree on
/// the arithmetic.
pub fn resample_len(in_len: usize, from: u32, to: u32) -> usize {
    if from == 0 {
        return 0;
    }
    ((in_len as u64 * to as u64) / from as u64) as usize
}

/// Linear resample of mono samples from `from` Hz to `to` Hz. Simple and
/// explicit; adequate for speech and easy to review. Equal rates copy through.
fn resample_mono(input: &[i16], from: u32, to: u32) -> Vec<i16> {
    if from == to || input.is_empty() {
        return input.to_vec();
    }
    let out_len = resample_len(input.len(), from, to);
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        // Position in the input in fractional samples.
        let pos = i as f64 * from as f64 / to as f64;
        let base = pos.floor() as usize;
        let frac = pos - base as f64;
        let a = to_f32(*input.get(base).unwrap_or(&0));
        let b = to_f32(*input.get(base + 1).unwrap_or(&input[input.len() - 1]));
        out.push(to_i16((a + (b - a) * frac as f32).clamp(-1.0, 1.0)));
    }
    out
}

// The setup closure and stream stay on the same thread until shutdown.
struct AudioThread {
    stop: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for AudioThread {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_audio_thread<T: Send + 'static>(
    setup: impl FnOnce() -> Result<(cpal::Stream, T), AudioDeviceError> + Send + 'static,
) -> Result<(AudioThread, T), AudioDeviceError> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::Builder::new()
        .spawn(move || match setup() {
            Ok((stream, data)) => {
                if ready_tx.send(Ok(data)).is_ok() {
                    let _ = stop_rx.recv();
                }
                drop(stream);
            }
            Err(error) => {
                let _ = ready_tx.send(Err(error));
            }
        })
        .map_err(|_| AudioDeviceError::Backend)?;
    let worker = AudioThread {
        stop: stop_tx,
        handle: Some(handle),
    };
    let data = ready_rx.recv().map_err(|_| AudioDeviceError::Backend)??;
    Ok((worker, data))
}
/// Captures the default (or named) input device, down-mixes to mono and
/// resamples to the codec rate, and hands the tick whole 20 ms frames.
pub struct CpalAudioInput {
    ring: Arc<SampleRing>,
    muted: Arc<AtomicBool>,
    _worker: AudioThread,
}

impl CpalAudioInput {
    pub fn new(choice: &DeviceChoice) -> Result<Self, AudioDeviceError> {
        let choice = choice.clone();
        let (worker, (ring, muted)) = start_audio_thread(move || {
            let host = cpal::default_host();
            let device = pick_input(&host, &choice)?;
            let supported = device.default_input_config().map_err(map_config_error)?;
            let device_rate = supported.sample_rate().0;
            let channels = supported.channels() as usize;
            let ring = Arc::new(SampleRing::new(RING_CAPACITY_SAMPLES));
            let muted = Arc::new(AtomicBool::new(false));
            let ring_cb = ring.clone();
            let muted_cb = muted.clone();
            // Mono scratch reused across callbacks lives inside the closure.
            let config: cpal::StreamConfig = supported.config();
            let err_fn = |_err: cpal::StreamError| {};
            let stream = device
                .build_input_stream(
                    &config,
                    move |data: &[f32], _: &cpal::InputCallbackInfo| {
                        // Never block: a short critical section pushing samples.
                        let mut mono = Vec::with_capacity(data.len() / channels.max(1) + 1);
                        down_mix(data, channels, &mut mono);
                        let at_codec = resample_mono(&mono, device_rate, CODEC_SAMPLE_RATE);
                        if muted_cb.load(Ordering::Relaxed) {
                            // Push silence of the same length so timing holds.
                            let silence = vec![0i16; at_codec.len()];
                            let _ = ring_cb.push(&silence);
                        } else {
                            let _ = ring_cb.push(&at_codec);
                        }
                    },
                    err_fn,
                    None,
                )
                .map_err(map_build_error)?;
            stream.play().map_err(|_| AudioDeviceError::Backend)?;
            Ok((stream, (ring, muted)))
        })?;
        Ok(Self {
            ring,
            muted,
            _worker: worker,
        })
    }

    /// Mute: the input keeps running but yields silence, so the far side hears
    /// nothing and the frame timing is unchanged.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Take the next 20 ms frame of mono codec-rate PCM, or `None` when not a
    /// full frame has accumulated yet (the tick then sends silence/no frame).
    pub fn next_frame(&mut self) -> Option<[i16; SAMPLES_PER_FRAME]> {
        if self.ring.len() < SAMPLES_PER_FRAME {
            return None;
        }
        let mut frame = [0i16; SAMPLES_PER_FRAME];
        let taken = self.ring.pop_into(&mut frame);
        if taken == 0 {
            None
        } else {
            Some(frame)
        }
    }
}

/// Writes decoded mono codec-rate PCM to the default (or named) output device,
/// resampling up to the device rate and fanning out to its channel count.
pub struct CpalAudioOutput {
    ring: Arc<SampleRing>,
    device_rate: u32,
    _worker: AudioThread,
}

impl CpalAudioOutput {
    pub fn new(choice: &DeviceChoice) -> Result<Self, AudioDeviceError> {
        let choice = choice.clone();
        let (worker, (ring, device_rate)) = start_audio_thread(move || {
            let host = cpal::default_host();
            let device = pick_output(&host, &choice)?;
            let supported = device.default_output_config().map_err(map_config_error)?;
            let device_rate = supported.sample_rate().0;
            let channels = supported.channels() as usize;
            // Hold enough device-rate mono audio that the callback rarely
            // underruns; sized in device-rate terms by the resample ratio. The
            // ring always stores device-rate mono samples, so the callback only
            // pops and fans out and never resamples.
            let capacity = resample_len(RING_CAPACITY_SAMPLES, CODEC_SAMPLE_RATE, device_rate)
                .max(RING_CAPACITY_SAMPLES);
            let ring = Arc::new(SampleRing::new(capacity));
            let ring_cb = ring.clone();
            let config: cpal::StreamConfig = supported.config();
            let err_fn = |_err: cpal::StreamError| {};
            let stream = device
                .build_output_stream(
                    &config,
                    move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                        // Never block: pull what is available, play silence for the
                        // rest (underrun), then fan mono out to all channels.
                        let needed = data.len() / channels.max(1);
                        let mut mono = vec![0i16; needed];
                        let _ = ring_cb.pop_into(&mut mono);
                        for (frame, &sample) in data.chunks_mut(channels.max(1)).zip(mono.iter()) {
                            let value = to_f32(sample);
                            for slot in frame.iter_mut() {
                                *slot = value;
                            }
                        }
                    },
                    err_fn,
                    None,
                )
                .map_err(map_build_error)?;
            stream.play().map_err(|_| AudioDeviceError::Backend)?;
            Ok((stream, (ring, device_rate)))
        })?;
        Ok(Self {
            ring,
            device_rate,
            _worker: worker,
        })
    }

    /// Queue one 20 ms frame of mono codec-rate PCM for playback. Resamples up
    /// to the device rate before buffering, so the callback only pops and
    /// never resamples; overflow drops the oldest inside the ring.
    pub fn play_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]) {
        let at_device = resample_mono(&frame[..], CODEC_SAMPLE_RATE, self.device_rate);
        let _ = self.ring.push(&at_device);
    }
}

/// Map a device-config query failure to a typed error, separating a denied
/// permission from a plain unsupported configuration where the backend tells
/// us. cpal does not expose a permission variant on every platform, so an
/// unknown cause is reported as `Unsupported` rather than guessed.
fn map_config_error(err: cpal::DefaultStreamConfigError) -> AudioDeviceError {
    match err {
        cpal::DefaultStreamConfigError::DeviceNotAvailable => AudioDeviceError::NoDevice,
        cpal::DefaultStreamConfigError::StreamTypeNotSupported => AudioDeviceError::Unsupported,
        cpal::DefaultStreamConfigError::BackendSpecific { .. } => AudioDeviceError::Backend,
    }
}

fn map_build_error(err: cpal::BuildStreamError) -> AudioDeviceError {
    match err {
        cpal::BuildStreamError::DeviceNotAvailable => AudioDeviceError::NoDevice,
        cpal::BuildStreamError::StreamConfigNotSupported => AudioDeviceError::Unsupported,
        cpal::BuildStreamError::InvalidArgument => AudioDeviceError::Unsupported,
        _ => AudioDeviceError::Backend,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_len_matches_ratio() {
        // Up: 960 at 48k becomes 1920 at 96k.
        assert_eq!(resample_len(960, 48_000, 96_000), 1920);
        // Down: 960 at 48k becomes 320 at 16k.
        assert_eq!(resample_len(960, 48_000, 16_000), 320);
        // Equal rate is identity.
        assert_eq!(resample_len(960, 48_000, 48_000), 960);
        // A zero source rate cannot divide; report nothing rather than panic.
        assert_eq!(resample_len(960, 0, 48_000), 0);
    }

    #[test]
    fn resample_mono_lengths_follow_resample_len() {
        let input = vec![1000i16; 480];
        let up = resample_mono(&input, 24_000, 48_000);
        assert_eq!(up.len(), resample_len(480, 24_000, 48_000));
        let down = resample_mono(&input, 48_000, 24_000);
        assert_eq!(down.len(), resample_len(480, 48_000, 24_000));
        let same = resample_mono(&input, 48_000, 48_000);
        assert_eq!(same.len(), 480);
    }

    #[test]
    fn ring_drops_oldest_on_overflow() {
        let ring = SampleRing::new(4);
        assert_eq!(ring.push(&[1, 2, 3, 4]), 0);
        // Pushing two more drops the two oldest.
        assert_eq!(ring.push(&[5, 6]), 2);
        let mut out = [0i16; 4];
        let taken = ring.pop_into(&mut out);
        assert_eq!(taken, 4);
        assert!(out == [3, 4, 5, 6]);
    }

    #[test]
    fn ring_underrun_leaves_silence() {
        let ring = SampleRing::new(8);
        ring.push(&[7, 7]);
        let mut out = [0i16; 4];
        let taken = ring.pop_into(&mut out);
        assert_eq!(taken, 2);
        // The unfilled tail stays as the pre-set silence.
        assert!(out == [7, 7, 0, 0]);
    }

    #[test]
    fn down_mix_averages_channels() {
        let mut out = Vec::new();
        // Two stereo frames: (1.0, -1.0) averages to 0; (0.5, 0.5) to 0.5.
        down_mix(&[1.0, -1.0, 0.5, 0.5], 2, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out[0].abs() < 2);
        assert!(out[1] > 0);
    }
}
