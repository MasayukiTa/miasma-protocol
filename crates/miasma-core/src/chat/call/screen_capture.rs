//! Primary-display capture for the screen-share stream (media_type 0x02).
//!
//! A real [`VideoSource`] over the primary monitor. The display handle may not
//! be `Send`, so it stays on a dedicated capture thread; that thread keeps only
//! the latest frame in a shared slot. Callers pull the latest frame with
//! [`VideoSource::next_picture`], which box-filter downscales the captured RGBA
//! to the codec size 160x120 limited-range BT.601 I420.
//!
//! Privacy: pictures hold opaque pixel bytes only; [`RawPicture`] does not
//! derive `Debug`, and no key, nonce, call id or peer id is stored, logged or
//! formatted here. Capture errors are typed and carry no captured content.

use super::video::{RawPicture, VideoSource};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use xcap::Monitor;

/// The codec picture size the screen stream is downscaled to.
const CAPTURE_WIDTH: usize = 160;
const CAPTURE_HEIGHT: usize = 120;

/// Upper bound on a single captured frame, as a guard before allocation or
/// downscaling. A 8K RGBA frame is ~132 MB; reject anything larger.
const MAX_SOURCE_DIM: usize = 8192;
const MAX_SOURCE_BYTES: usize = 256 * 1024 * 1024;

/// A captured RGBA frame handed from the capture thread to the consumer.
struct Captured {
    width: usize,
    height: usize,
    rgba: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenError {
    NoDisplay,
    PermissionDenied,
    Backend,
}

/// Captures the primary display. The monitor handle stays on the capture
/// thread; only the latest frame crosses back through a mutex-guarded slot.
pub struct ScreenSource {
    slot: Arc<Mutex<Option<Captured>>>,
    stop: Arc<AtomicBool>,
    open: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ScreenSource {
    pub fn new() -> Result<Self, ScreenError> {
        let slot = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let open = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("screen-capture".into())
            .spawn({
                let slot = slot.clone();
                let stop = stop.clone();
                let open = open.clone();
                move || capture_loop(slot, stop, open, tx)
            })
            .map_err(|_| ScreenError::Backend)?;
        let source = Self {
            slot,
            stop,
            open,
            worker: Some(worker),
        };
        match rx.recv() {
            Ok(Ok(())) => Ok(source),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ScreenError::Backend),
        }
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.open.store(false, Ordering::Release);
        if let Ok(mut slot) = self.slot.lock() {
            *slot = None;
        }
    }
}

// The monitor handle lives and dies inside this function, so it never has to be
// `Send`. The loop keeps only the most recent frame in the shared slot.
fn capture_loop(
    slot: Arc<Mutex<Option<Captured>>>,
    stop: Arc<AtomicBool>,
    open: Arc<AtomicBool>,
    tx: mpsc::SyncSender<Result<(), ScreenError>>,
) {
    let monitor = match primary_monitor() {
        Ok(monitor) => monitor,
        Err(e) => {
            let _ = tx.send(Err(e));
            return;
        }
    };
    open.store(true, Ordering::Release);
    if tx.send(Ok(())).is_err() {
        open.store(false, Ordering::Release);
        return;
    }
    while !stop.load(Ordering::Acquire) {
        match capture_once(&monitor) {
            Ok(frame) => {
                if let Ok(mut guard) = slot.try_lock() {
                    *guard = Some(frame);
                }
            }
            Err(_) => break,
        }
    }
    open.store(false, Ordering::Release);
    if let Ok(mut guard) = slot.try_lock() {
        *guard = None;
    }
}

fn primary_monitor() -> Result<Monitor, ScreenError> {
    let monitors = Monitor::all().map_err(classify_error)?;
    if let Some(monitor) = monitors
        .iter()
        .find(|m| m.is_primary().unwrap_or(false))
        .cloned()
    {
        return Ok(monitor);
    }
    monitors.into_iter().next().ok_or(ScreenError::NoDisplay)
}

fn capture_once(monitor: &Monitor) -> Result<Captured, ScreenError> {
    let image = monitor.capture_image().map_err(classify_error)?;
    let width = image.width() as usize;
    let height = image.height() as usize;
    let rgba = image.into_raw();
    if width == 0
        || height == 0
        || width > MAX_SOURCE_DIM
        || height > MAX_SOURCE_DIM
        || rgba.len() > MAX_SOURCE_BYTES
        || rgba.len() != width.saturating_mul(height).saturating_mul(4)
    {
        return Err(ScreenError::Backend);
    }
    Ok(Captured {
        width,
        height,
        rgba,
    })
}

fn classify_error(error: xcap::XCapError) -> ScreenError {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("access denied")
        || text.contains("permission denied")
        || text.contains("0x80070005")
    {
        ScreenError::PermissionDenied
    } else {
        ScreenError::Backend
    }
}

impl Drop for ScreenSource {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl VideoSource for ScreenSource {
    fn is_open(&self) -> bool {
        ScreenSource::is_open(self)
    }

    fn next_picture(&mut self) -> Option<RawPicture> {
        if !self.is_open() {
            return None;
        }
        let frame = self.slot.try_lock().ok()?.take()?;
        let pixels = rgba_to_i420(
            &frame.rgba,
            frame.width,
            frame.height,
            CAPTURE_WIDTH,
            CAPTURE_HEIGHT,
        )?;
        Some(RawPicture {
            width: CAPTURE_WIDTH as u16,
            height: CAPTURE_HEIGHT as u16,
            pixels,
        })
    }
}

/// The default [`ScreenSourceFactory`]: opens the primary display on demand.
/// Held by the call runtime in real builds; tests substitute a fake factory.
pub struct PrimaryScreenFactory;

impl super::video::ScreenSourceFactory for PrimaryScreenFactory {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>> {
        ScreenSource::new()
            .ok()
            .map(|source| Box::new(source) as Box<dyn VideoSource + Send>)
    }
}

/// Box-filter downscale RGBA `w`x`h` to limited-range BT.601 I420 at
/// `width`x`height`. Each destination pixel averages the source box that maps
/// to it, so shrinking does not alias the way nearest-neighbour would. `width`
/// and `height` must be even and non-zero; returns `None` on any size mismatch.
fn rgba_to_i420(rgba: &[u8], w: usize, h: usize, width: usize, height: usize) -> Option<Vec<u8>> {
    if w == 0
        || h == 0
        || width == 0
        || height == 0
        || width % 2 != 0
        || height % 2 != 0
        || width > MAX_SOURCE_DIM
        || height > MAX_SOURCE_DIM
        || w > MAX_SOURCE_DIM
        || h > MAX_SOURCE_DIM
        || rgba.len() != w.checked_mul(h)?.checked_mul(4)?
    {
        return None;
    }
    let n = width.checked_mul(height)?;
    let mut out = vec![0u8; n.checked_add(n / 2)?];
    // Luma: one box average per destination pixel.
    for y in 0..height {
        let sy0 = y * h / height;
        let sy1 = ((y + 1) * h / height).max(sy0 + 1).min(h);
        for x in 0..width {
            let sx0 = x * w / width;
            let sx1 = ((x + 1) * w / width).max(sx0 + 1).min(w);
            let (r, g, b) = box_average_rgb(rgba, w, sx0, sx1, sy0, sy1);
            out[y * width + x] =
                (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8;
        }
    }
    // Chroma: one box average per 2x2 destination block.
    for y in (0..height).step_by(2) {
        let sy0 = y * h / height;
        let sy1 = ((y + 2) * h / height).max(sy0 + 1).min(h);
        for x in (0..width).step_by(2) {
            let sx0 = x * w / width;
            let sx1 = ((x + 2) * w / width).max(sx0 + 1).min(w);
            let (r, g, b) = box_average_rgb(rgba, w, sx0, sx1, sy0, sy1);
            let u = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
            let v = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
            let i = (y / 2) * (width / 2) + x / 2;
            out[n + i] = u;
            out[n + n / 4 + i] = v;
        }
    }
    Some(out)
}

// Average the RGB channels of the source box [sx0,sx1) x [sy0,sy1). The range
// is clamped non-empty by the caller, so the divisor is never zero.
fn box_average_rgb(
    rgba: &[u8],
    w: usize,
    sx0: usize,
    sx1: usize,
    sy0: usize,
    sy1: usize,
) -> (i32, i32, i32) {
    let mut r = 0i64;
    let mut g = 0i64;
    let mut b = 0i64;
    let mut count = 0i64;
    for sy in sy0..sy1 {
        for sx in sx0..sx1 {
            let i = (sy * w + sx) * 4;
            r += rgba[i] as i64;
            g += rgba[i + 1] as i64;
            b += rgba[i + 2] as i64;
            count += 1;
        }
    }
    let count = count.max(1);
    ((r / count) as i32, (g / count) as i32, (b / count) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn source_is_send() {
        assert_send::<ScreenSource>();
    }

    #[test]
    fn captured_is_send() {
        assert_send::<Captured>();
    }

    // Solid colour box-filters to that same colour regardless of scale factor.
    #[test]
    fn solid_colour_downscale() {
        // 4x4 solid white RGBA -> 2x2 I420. White maps to Y=235, U=V=128.
        let rgba = vec![255u8; 4 * 4 * 4];
        let out = rgba_to_i420(&rgba, 4, 4, 2, 2).unwrap();
        assert!(out == vec![235, 235, 235, 235, 128, 128]);
    }

    // Box filter averages, unlike nearest-neighbour. A 2x1 split of black and
    // white averaged into a single pixel is mid-grey, not either endpoint.
    #[test]
    fn box_filter_averages() {
        // 2x2 RGBA: left column black, right column white.
        let rgba = vec![
            0, 0, 0, 255, 255, 255, 255, 255, // row 0
            0, 0, 0, 255, 255, 255, 255, 255, // row 1
        ];
        // Downscale 2x2 -> 2x2 keeps columns distinct (identity-ish).
        let identity = rgba_to_i420(&rgba, 2, 2, 2, 2).unwrap();
        assert!(identity[0] == 16); // black -> Y 16
        assert!(identity[1] == 235); // white -> Y 235
                                     // Downscale 2x2 -> single-column would need width 2; instead check that
                                     // box_average over the whole row yields the mid grey of black+white.
        let (r, g, b) = box_average_rgb(&rgba, 2, 0, 2, 0, 1);
        assert!((r, g, b) == (127, 127, 127));
    }

    #[test]
    fn rejects_bad_sizes() {
        let rgba = vec![0u8; 2 * 2 * 4];
        assert!(rgba_to_i420(&rgba, 2, 2, 3, 2) == None); // odd width
        assert!(rgba_to_i420(&rgba, 2, 2, 2, 0) == None); // zero height
        assert!(rgba_to_i420(&rgba, usize::MAX, 2, 2, 2) == None); // overflow
        assert!(rgba_to_i420(&rgba, 4, 4, 2, 2) == None); // length mismatch
    }
}
