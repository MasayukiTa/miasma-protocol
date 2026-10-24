//! Reading a contact code from a picture of a QR code (a saved screenshot or a photo).
//!
//! The picture is untrusted input. This module only turns bytes into the text of a contact code;
//! what happens to that text afterwards is the same as for a pasted code (the add-contact form
//! checks it with `miasma_core::push::extract_contact_code`).
//!
//! Limits, each against a concrete case:
//! * [`MAX_FILE_BYTES`]: the file is read into memory, so a file of any size would be read whole.
//! * [`MAX_PIXELS`]: a small PNG can declare an enormous width and height. The size is read from
//!   the header first and a picture above the limit is refused before any pixel buffer is made.
//!   24 megapixels is a 20 MP camera photo; the grey buffer made from it is 24 MB and the decoded
//!   RGB picture about 72 MB at its largest.
//! * [`MAX_GRIDS`]: a picture of many codes would otherwise be decoded code by code without end.
//!
//! Nothing here logs, prints or stores picture content or decoded text, and no temporary file is
//! made.

use std::io::{Cursor, Read};
use std::path::Path;

/// Largest picture file that is read.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Largest picture, in pixels (width times height), that is decoded.
pub const MAX_PIXELS: u64 = 24_000_000;
/// Smallest side that can hold a QR code (version 1 is 21 modules).
const MIN_SIDE: u32 = 21;
/// Most QR codes tried in one picture.
const MAX_GRIDS: usize = 4;
/// Ceiling for what the image decoders may allocate at once.
const MAX_DECODER_ALLOC: u64 = 256 * 1024 * 1024;

/// Why a picture gave no contact code. Each one has its own sentence in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrImageError {
    /// The file could not be opened or read.
    Unreadable,
    /// Not a PNG or JPEG picture, or a damaged one.
    NotImage,
    /// The file or the picture is above a limit.
    TooLarge,
    /// A picture, but no QR code could be read in it.
    NoQr,
    /// A QR code was read, but its text holds no Miasma contact code.
    NotMiasma,
}

/// Read the file into memory, refusing anything above [`MAX_FILE_BYTES`] without reading it all.
pub fn read_limited(path: &Path) -> Result<Vec<u8>, QrImageError> {
    let file = std::fs::File::open(path).map_err(|_| QrImageError::Unreadable)?;
    let meta = file.metadata().map_err(|_| QrImageError::Unreadable)?;
    if !meta.is_file() {
        return Err(QrImageError::Unreadable);
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(QrImageError::TooLarge);
    }
    // The size can change after the check: read one byte more than the limit and compare.
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| QrImageError::Unreadable)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(QrImageError::TooLarge);
    }
    Ok(bytes)
}

/// The texts of the QR codes found in a PNG or JPEG picture (at most [`MAX_GRIDS`]).
///
/// Pure and total: any bytes give `Ok` or an error, never a panic.
// `Limits` cannot be built with a struct literal outside its crate (it is non-exhaustive).
#[allow(clippy::field_reassign_with_default)]
pub fn decode_qr_texts(bytes: &[u8]) -> Result<Vec<String>, QrImageError> {
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(QrImageError::TooLarge);
    }
    let reader = || {
        image::io::Reader::new(Cursor::new(bytes))
            .with_guessed_format()
            .map_err(|_| QrImageError::NotImage)
    };
    let first = reader()?;
    if !matches!(
        first.format(),
        Some(image::ImageFormat::Png) | Some(image::ImageFormat::Jpeg)
    ) {
        return Err(QrImageError::NotImage);
    }
    // The size comes from the header alone; nothing is allocated for the pixels yet.
    let (w, h) = first
        .into_dimensions()
        .map_err(|_| QrImageError::NotImage)?;
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(QrImageError::TooLarge);
    }
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(QrImageError::NoQr);
    }
    let mut second = reader()?;
    let mut limits = image::io::Limits::default();
    limits.max_image_width = Some(w);
    limits.max_image_height = Some(h);
    limits.max_alloc = Some(MAX_DECODER_ALLOC);
    second.limits(limits);
    let grey = second
        .decode()
        .map_err(|_| QrImageError::NotImage)?
        .to_luma8();
    let (w, h) = (grey.width() as usize, grey.height() as usize);
    let raw = grey.as_raw();
    // The scanner is third-party code run on untrusted pixels: a panic inside it is "no code".
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| raw[y * w + x]);
        prepared
            .detect_grids()
            .into_iter()
            .take(MAX_GRIDS)
            .filter_map(|g| g.decode().ok().map(|(_, text)| text))
            .collect::<Vec<String>>()
    }))
    .unwrap_or_default();
    if found.is_empty() {
        Err(QrImageError::NoQr)
    } else {
        Ok(found)
    }
}

/// The contact code in a picture. The text of a QR code goes through the same check as a pasted
/// text (`extract_contact_code`); the first code that holds a contact code wins.
pub fn contact_code_from_image(bytes: &[u8]) -> Result<String, QrImageError> {
    decode_qr_texts(bytes)?
        .iter()
        .find_map(|t| miasma_core::push::extract_contact_code(t))
        .ok_or(QrImageError::NotMiasma)
}

/// Read the file and find the contact code in it. Runs on a helper thread.
pub fn contact_code_from_file(path: &Path) -> Result<String, QrImageError> {
    // A panic in a decoder must not leave the window waiting for an answer that never comes.
    std::panic::catch_unwind(|| contact_code_from_image(&read_limited(path)?))
        .unwrap_or(Err(QrImageError::NotImage))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use image::{DynamicImage, GrayImage, ImageFormat, Luma};

    /// A fresh valid contact code (a random key that is a point on the curve; about half of all
    /// random values are, so a few draws are enough).
    pub(crate) fn fresh_code() -> String {
        loop {
            let id: [u8; 32] = rand::random();
            let text = miasma_core::push::ContactCode::new(id).to_string();
            if miasma_core::push::ContactCode::parse(&text).is_ok() {
                return text;
            }
        }
    }

    /// The QR picture of `text`: `scale` pixels per module, a quiet zone of four modules.
    fn qr_picture(text: &str, scale: u32) -> GrayImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let n = code.width() as u32;
        let colors = code.to_colors();
        let side = (n + 8) * scale;
        GrayImage::from_fn(side, side, |x, y| {
            let (mx, my) = (x / scale, y / scale);
            let dark = (4..4 + n).contains(&mx)
                && (4..4 + n).contains(&my)
                && colors[((my - 4) * n + (mx - 4)) as usize] == qrcode::Color::Dark;
            Luma([if dark { 0 } else { 255 }])
        })
    }

    fn encode(img: &GrayImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageLuma8(img.clone())
            .write_to(&mut out, format)
            .unwrap();
        out.into_inner()
    }

    pub(crate) fn png_of(text: &str, scale: u32) -> Vec<u8> {
        encode(&qr_picture(text, scale), ImageFormat::Png)
    }

    /// Rotate by `deg` degrees around the centre onto a white square large enough for the corners
    /// (nearest pixel; enough for a code with a quiet zone).
    fn rotated(img: &GrayImage, deg: f32) -> GrayImage {
        let side = img.width() as f32;
        let out_side = (side * 1.5).ceil() as u32;
        let (c_in, c_out) = (side / 2.0, out_side as f32 / 2.0);
        let (s, c) = deg.to_radians().sin_cos();
        GrayImage::from_fn(out_side, out_side, |x, y| {
            let (dx, dy) = (x as f32 - c_out, y as f32 - c_out);
            let (sx, sy) = (c * dx + s * dy + c_in, -s * dx + c * dy + c_in);
            if sx >= 0.0 && sy >= 0.0 && sx < side && sy < side {
                *img.get_pixel(sx as u32, sy as u32)
            } else {
                Luma([255])
            }
        })
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(body);
        out.extend_from_slice(&crc_input);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out
    }

    /// A PNG that only declares `w` x `h` pixels: a header, one tiny data chunk and the end.
    fn png_declaring(w: u32, h: u32) -> Vec<u8> {
        let mut ihdr = w.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        out.extend(chunk(b"IHDR", &ihdr));
        out.extend(chunk(
            b"IDAT",
            &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01],
        ));
        out.extend(chunk(b"IEND", &[]));
        out
    }

    #[test]
    fn a_png_of_a_contact_code_is_read_back_exactly() {
        let code = fresh_code();
        for scale in [3, 8] {
            let text = crate::contacts::qr_payload(&code);
            let got = contact_code_from_image(&png_of(&text, scale)).unwrap();
            assert_eq!(got, code, "scale {scale}");
        }
    }

    #[test]
    fn a_jpeg_of_a_contact_code_is_read_back() {
        let code = fresh_code();
        let text = crate::contacts::qr_payload(&code);
        let jpeg = encode(&qr_picture(&text, 8), ImageFormat::Jpeg);
        assert_eq!(contact_code_from_image(&jpeg).unwrap(), code);
    }

    #[test]
    fn a_rotated_and_a_turned_picture_are_read() {
        let code = fresh_code();
        let text = crate::contacts::qr_payload(&code);
        let base = qr_picture(&text, 6);
        for turned in [
            image::imageops::rotate90(&base),
            image::imageops::rotate180(&base),
            rotated(&base, 30.0),
        ] {
            let png = encode(&turned, ImageFormat::Png);
            assert_eq!(contact_code_from_image(&png).unwrap(), code);
        }
    }

    #[test]
    fn the_text_goes_through_the_same_check_as_a_pasted_text() {
        let code = fresh_code();
        // Some other text around the code, as in an invitation message.
        let text = format!("Hello\n{code}\nbye");
        assert_eq!(contact_code_from_image(&png_of(&text, 4)).unwrap(), code);
        assert_eq!(
            miasma_core::push::extract_contact_code(&text).as_deref(),
            Some(code.as_str())
        );
    }

    #[test]
    fn a_qr_code_that_is_not_a_contact_code_is_refused() {
        for text in [
            "https://example.org/".to_owned(),
            "miasma-contact:notacode".to_owned(),
            // A code with one character changed: the checksum no longer matches.
            {
                let mut c = fresh_code();
                let last = c.pop().unwrap();
                c.push(if last == '2' { '3' } else { '2' });
                c
            },
        ] {
            assert_eq!(
                contact_code_from_image(&png_of(&text, 4)),
                Err(QrImageError::NotMiasma),
                "{text}"
            );
        }
    }

    #[test]
    fn a_picture_without_a_qr_code_says_so() {
        let blank = GrayImage::from_pixel(120, 120, Luma([255]));
        assert_eq!(
            contact_code_from_image(&encode(&blank, ImageFormat::Png)),
            Err(QrImageError::NoQr)
        );
        // Too small to hold a code at all.
        let tiny = GrayImage::from_pixel(5, 5, Luma([0]));
        assert_eq!(
            contact_code_from_image(&encode(&tiny, ImageFormat::Png)),
            Err(QrImageError::NoQr)
        );
    }

    #[test]
    fn things_that_are_not_pictures_are_refused_without_a_panic() {
        let good = png_of(&fresh_code(), 4);
        let mut cut = good.clone();
        cut.truncate(good.len() / 2);
        let mut damaged = good.clone();
        for b in damaged.iter_mut().skip(40).step_by(7) {
            *b ^= 0x5a;
        }
        let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;".to_vec();
        for bytes in [
            Vec::new(),
            b"just some text".to_vec(),
            vec![0xff; 64],
            gif,
            cut,
            damaged,
            good[..8].to_vec(),
            // A JPEG start marker and nothing more.
            vec![0xff, 0xd8, 0xff, 0xe0, 0, 0],
        ] {
            let r = contact_code_from_image(&bytes);
            assert!(
                matches!(r, Err(QrImageError::NotImage | QrImageError::NoQr)),
                "{r:?}"
            );
        }
    }

    #[test]
    fn a_huge_declared_size_is_refused_from_the_header() {
        // 60000 x 60000 would need 3.6 GB of pixels; the data chunk is a few bytes.
        assert_eq!(
            contact_code_from_image(&png_declaring(60_000, 60_000)),
            Err(QrImageError::TooLarge)
        );
        // Each side is modest and the area is just above the limit.
        assert_eq!(
            contact_code_from_image(&png_declaring(4_000, 6_001)),
            Err(QrImageError::TooLarge)
        );
        // 4000 x 6000 is exactly the limit: it passes the size check (then the data is bad).
        assert_ne!(
            contact_code_from_image(&png_declaring(4_000, 6_000)),
            Err(QrImageError::TooLarge)
        );
    }

    #[test]
    fn a_file_above_the_size_limit_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.png");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_FILE_BYTES + 1).unwrap();
        drop(f);
        assert_eq!(read_limited(&path), Err(QrImageError::TooLarge));
        assert_eq!(
            decode_qr_texts(&vec![0u8; (MAX_FILE_BYTES + 1) as usize]),
            Err(QrImageError::TooLarge)
        );
        assert_eq!(
            read_limited(&dir.path().join("missing.png")),
            Err(QrImageError::Unreadable)
        );
        assert_eq!(read_limited(dir.path()), Err(QrImageError::Unreadable));
    }

    #[test]
    fn a_file_on_disk_is_read_like_the_bytes() {
        let code = fresh_code();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code.png");
        std::fs::write(&path, png_of(&code, 5)).unwrap();
        assert_eq!(contact_code_from_file(&path).unwrap(), code);
    }
}
