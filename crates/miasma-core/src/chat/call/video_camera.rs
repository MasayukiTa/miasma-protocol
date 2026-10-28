//! Default camera capture. Pictures contain limited-range BT.601 I420 planes.
use super::video::{RawPicture, VideoSource};
use nokhwa::{
    buffer::Buffer,
    pixel_format::RgbFormat,
    types::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CameraError {
    NoCamera,
    PermissionDenied,
    Backend,
}

/// The device itself stays on the capture thread.
pub struct CameraSource {
    slot: Arc<Mutex<Option<Buffer>>>,
    stop: Arc<AtomicBool>,
    open: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl CameraSource {
    pub fn new() -> Result<Self, CameraError> {
        let mut source = Self {
            slot: Arc::new(Mutex::new(None)),
            stop: Arc::new(AtomicBool::new(false)),
            open: Arc::new(AtomicBool::new(false)),
            worker: None,
        };
        source.set_enabled(true)?;
        Ok(source)
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Disabling waits for capture to stop and releases the device; enabling reopens it.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), CameraError> {
        if !enabled {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            self.open.store(false, Ordering::Release);
            if let Ok(mut slot) = self.slot.lock() {
                *slot = None;
            }
            return Ok(());
        }
        if self.is_open() {
            return Ok(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.stop.store(false, Ordering::Release);
        let stop = self.stop.clone();
        let open = self.open.clone();
        let slot = self.slot.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("camera-capture".into())
            .spawn(move || {
                #[cfg(target_os = "macos")]
                {
                    let _ = tx.send(Err(CameraError::Backend));
                    return;
                }
                #[cfg(windows)]
                {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let devices = nokhwa::query(nokhwa::utils::ApiBackend::MediaFoundation)
                            .map_err(classify_error)?;
                        if devices.is_empty() {
                            return Err(CameraError::NoCamera);
                        }
                        let format = RequestedFormat::new::<RgbFormat>(
                            RequestedFormatType::AbsoluteHighestFrameRate,
                        );
                        let mut camera =
                            Camera::new(CameraIndex::Index(0), format).map_err(classify_error)?;
                        camera.open_stream().map_err(classify_error)?;
                        open.store(true, Ordering::Release);
                        if tx.send(Ok(())).is_err() {
                            return Ok(());
                        }
                        while !stop.load(Ordering::Acquire) {
                            match camera.frame() {
                                Ok(frame) => {
                                    if let Ok(mut guard) = slot.try_lock() {
                                        *guard = Some(frame);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        Ok(())
                    }));
                    open.store(false, Ordering::Release);
                    if let Ok(mut guard) = slot.try_lock() {
                        *guard = None;
                    }
                    match result {
                        Ok(Err(e)) => {
                            let _ = tx.send(Err(e));
                        }
                        Err(_) => {
                            let _ = tx.send(Err(CameraError::Backend));
                        }
                        _ => {}
                    }
                }
            })
            .map_err(|_| CameraError::Backend)?;
        self.worker = Some(worker);
        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                let _ = self.set_enabled(false);
                Err(e)
            }
            Err(_) => {
                let _ = self.set_enabled(false);
                Err(CameraError::Backend)
            }
        }
    }
}

#[cfg(windows)]
fn classify_error(error: nokhwa::error::NokhwaError) -> CameraError {
    // Nokhwa exposes backend errors as strings, so only explicit access failures
    // can be classified; all other failures remain Backend.
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("access denied")
        || text.contains("permission denied")
        || text.contains("0x80070005")
    {
        CameraError::PermissionDenied
    } else {
        CameraError::Backend
    }
}

impl Drop for CameraSource {
    fn drop(&mut self) {
        let _ = self.set_enabled(false);
    }
}
impl VideoSource for CameraSource {
    fn next_picture(&mut self) -> Option<RawPicture> {
        if !self.is_open() {
            return None;
        }
        let frame = self.slot.try_lock().ok()?.take()?;
        let pixels = convert(&frame, 320, 240)?;
        Some(RawPicture {
            width: 320,
            height: 240,
            pixels,
        })
    }
}

// Decode the camera format to RGB, then nearest-neighbour sample and convert.
// Bound dimensions before calling the backend decoder, and contain decoder panics.
fn convert(frame: &Buffer, width: usize, height: usize) -> Option<Vec<u8>> {
    let res = frame.resolution();
    let (w, h) = (
        usize::try_from(res.width_x).ok()?,
        usize::try_from(res.height_y).ok()?,
    );
    if w == 0 || h == 0 || w > 8192 || h > 8192 || frame.buffer().len() > 128 * 1024 * 1024 {
        return None;
    }
    let image = std::panic::catch_unwind(|| frame.decode_image::<RgbFormat>())
        .ok()?
        .ok()?;
    rgb_to_i420(image.as_raw(), w, h, width, height)
}

fn rgb_to_i420(rgb: &[u8], w: usize, h: usize, width: usize, height: usize) -> Option<Vec<u8>> {
    if w == 0
        || h == 0
        || width == 0
        || height == 0
        || width % 2 != 0
        || height % 2 != 0
        || width > 8192
        || height > 8192
        || w > 8192
        || h > 8192
        || rgb.len() != w.checked_mul(h)?.checked_mul(3)?
    {
        return None;
    }
    let n = width.checked_mul(height)?;
    let mut out = vec![0; n.checked_add(n / 2)?];
    for y in 0..height {
        for x in 0..width {
            let i = ((y * h / height) * w + x * w / width) * 3;
            let (r, g, b) = (rgb[i] as i32, rgb[i + 1] as i32, rgb[i + 2] as i32);
            out[y * width + x] =
                (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8;
        }
    }
    for y in (0..height).step_by(2) {
        for x in (0..width).step_by(2) {
            let mut u = 0;
            let mut v = 0;
            for dy in 0..2 {
                for dx in 0..2 {
                    let i = (((y + dy) * h / height) * w + (x + dx) * w / width) * 3;
                    let (r, g, b) = (rgb[i] as i32, rgb[i + 1] as i32, rgb[i + 2] as i32);
                    u += (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255);
                    v += (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255);
                }
            }
            let i = (y / 2) * (width / 2) + x / 2;
            out[n + i] = ((u + 2) / 4) as u8;
            out[n + n / 4 + i] = ((v + 2) / 4) as u8;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nokhwa::utils::{FrameFormat, Resolution};
    fn assert_send<T: Send>() {}
    #[test]
    fn source_is_send() {
        assert_send::<CameraSource>();
    }
    #[test]
    fn bgr_and_yuy2() {
        let bgr = Buffer::new(
            Resolution::new(2, 2),
            &[0, 0, 0, 255, 255, 255, 0, 0, 0, 255, 255, 255],
            FrameFormat::RAWBGR,
        );
        assert_eq!(convert(&bgr, 2, 2), Some(vec![16, 235, 16, 235, 128, 128]));
        let yuy2 = Buffer::new(
            Resolution::new(2, 2),
            &[16, 128, 235, 128, 16, 128, 235, 128],
            FrameFormat::YUYV,
        );
        let out = convert(&yuy2, 2, 2).unwrap();
        assert_eq!(out, vec![16, 235, 16, 235, 128, 128]);
        assert_eq!(&out[4..], &[128, 128]);
    }
    #[test]
    fn mjpeg_black() {
        let frame = Buffer::new(
            Resolution::new(2, 2),
            include_bytes!("camera_black.jpg"),
            FrameFormat::MJPEG,
        );
        assert_eq!(convert(&frame, 2, 2), Some(vec![16, 16, 16, 16, 128, 128]));
    }
    #[test]
    fn nearest_and_invalid() {
        let rgb = [0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0];
        assert_eq!(
            rgb_to_i420(&rgb, 2, 2, 4, 2),
            Some(vec![16, 16, 235, 235, 235, 235, 16, 16, 128, 128, 128, 128])
        );
        assert_eq!(rgb_to_i420(&rgb, usize::MAX, 2, 2, 2), None);
        assert_eq!(
            convert(
                &Buffer::new(Resolution::new(2, 2), &[1, 2], FrameFormat::MJPEG),
                2,
                2
            ),
            None
        );
    }
}
