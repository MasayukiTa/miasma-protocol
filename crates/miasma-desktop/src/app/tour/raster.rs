//! A small CPU rasteriser for egui's tessellated output, used by the window-less UI tour.
//!
//! It needs no window, no GPU and no OpenGL: the meshes egui produces are filled triangle by
//! triangle into an RGB buffer with premultiplied-alpha blending in gamma space, which is what
//! egui's own OpenGL painter does. Output is a 24-bit BMP.

use std::collections::HashMap;

use eframe::egui::{
    self, epaint::Primitive, ClippedPrimitive, Color32, ImageData, TextureId, TexturesDelta,
};

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

#[derive(Default)]
pub struct Renderer {
    texs: HashMap<TextureId, Tex>,
}

impl Renderer {
    /// Apply the texture uploads egui asked for this frame (the font atlas, mostly).
    pub fn apply(&mut self, delta: &TexturesDelta) {
        for (id, d) in &delta.set {
            let (w, h, px): (usize, usize, Vec<Color32>) = match &d.image {
                ImageData::Color(c) => (c.size[0], c.size[1], c.pixels.clone()),
                ImageData::Font(f) => (f.size[0], f.size[1], f.srgba_pixels(None).collect()),
            };
            match d.pos {
                None => {
                    self.texs.insert(*id, Tex { w, h, px });
                }
                Some([x0, y0]) => {
                    if let Some(t) = self.texs.get_mut(id) {
                        for y in 0..h {
                            for x in 0..w {
                                let (tx, ty) = (x0 + x, y0 + y);
                                if tx < t.w && ty < t.h {
                                    t.px[ty * t.w + tx] = px[y * w + x];
                                }
                            }
                        }
                    }
                }
            }
        }
        for id in &delta.free {
            self.texs.remove(id);
        }
    }

    /// Paint the primitives (points == pixels) into a `w` x `h` RGB buffer on `bg`.
    pub fn paint(&self, prims: &[ClippedPrimitive], w: usize, h: usize, bg: [u8; 3]) -> Vec<u8> {
        let mut fb = vec![0u8; w * h * 3];
        for p in fb.chunks_exact_mut(3) {
            p.copy_from_slice(&bg);
        }
        for prim in prims {
            let Primitive::Mesh(mesh) = &prim.primitive else {
                continue;
            };
            let Some(tex) = self.texs.get(&mesh.texture_id) else {
                continue;
            };
            let clip = prim.clip_rect;
            let cx0 = clip.min.x.max(0.0).floor() as i64;
            let cy0 = clip.min.y.max(0.0).floor() as i64;
            let cx1 = (clip.max.x.min(w as f32)).ceil() as i64;
            let cy1 = (clip.max.y.min(h as f32)).ceil() as i64;
            for tri in mesh.indices.chunks_exact(3) {
                let v = [
                    mesh.vertices[tri[0] as usize],
                    mesh.vertices[tri[1] as usize],
                    mesh.vertices[tri[2] as usize],
                ];
                fill_triangle(&mut fb, w, tex, &v, (cx0, cy0, cx1, cy1));
            }
        }
        fb
    }
}

fn edge(ax: f32, ay: f32, bx: f32, by: f32, px: f32, py: f32) -> f32 {
    (bx - ax) * (py - ay) - (by - ay) * (px - ax)
}

/// Top-left fill rule for a triangle wound with positive area, so a pixel centre that lies
/// exactly on a shared edge is painted once, not twice.
fn owns_edge(ax: f32, ay: f32, bx: f32, by: f32) -> bool {
    let (dx, dy) = (bx - ax, by - ay);
    dy < 0.0 || (dy == 0.0 && dx > 0.0)
}

fn sample(tex: &Tex, u: f32, v: f32) -> [f32; 4] {
    let x = u * tex.w as f32 - 0.5;
    let y = v * tex.h as f32 - 0.5;
    let (x0, y0) = (x.floor(), y.floor());
    let (fx, fy) = (x - x0, y - y0);
    let at = |ix: f32, iy: f32| -> [f32; 4] {
        let cx = (ix.max(0.0) as usize).min(tex.w - 1);
        let cy = (iy.max(0.0) as usize).min(tex.h - 1);
        let c = tex.px[cy * tex.w + cx];
        [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
    };
    let (a, b, c, d) = (
        at(x0, y0),
        at(x0 + 1.0, y0),
        at(x0, y0 + 1.0),
        at(x0 + 1.0, y0 + 1.0),
    );
    let mut out = [0.0; 4];
    for i in 0..4 {
        let top = a[i] * (1.0 - fx) + b[i] * fx;
        let bot = c[i] * (1.0 - fx) + d[i] * fx;
        out[i] = top * (1.0 - fy) + bot * fy;
    }
    out
}

fn fill_triangle(
    fb: &mut [u8],
    fw: usize,
    tex: &Tex,
    v: &[egui::epaint::Vertex; 3],
    clip: (i64, i64, i64, i64),
) {
    let (p0, mut p1, mut p2) = (v[0], v[1], v[2]);
    let area = edge(p0.pos.x, p0.pos.y, p1.pos.x, p1.pos.y, p2.pos.x, p2.pos.y);
    if area == 0.0 || !area.is_finite() {
        return;
    }
    if area < 0.0 {
        std::mem::swap(&mut p1, &mut p2);
    }
    let area = area.abs();
    let min_x = p0.pos.x.min(p1.pos.x).min(p2.pos.x).floor() as i64;
    let max_x = p0.pos.x.max(p1.pos.x).max(p2.pos.x).ceil() as i64;
    let min_y = p0.pos.y.min(p1.pos.y).min(p2.pos.y).floor() as i64;
    let max_y = p0.pos.y.max(p1.pos.y).max(p2.pos.y).ceil() as i64;
    let (x0, x1) = (min_x.max(clip.0), max_x.min(clip.2));
    let (y0, y1) = (min_y.max(clip.1), max_y.min(clip.3));
    let own = [
        owns_edge(p1.pos.x, p1.pos.y, p2.pos.x, p2.pos.y),
        owns_edge(p2.pos.x, p2.pos.y, p0.pos.x, p0.pos.y),
        owns_edge(p0.pos.x, p0.pos.y, p1.pos.x, p1.pos.y),
    ];
    for y in y0..y1 {
        for x in x0..x1 {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let w0 = edge(p1.pos.x, p1.pos.y, p2.pos.x, p2.pos.y, px, py);
            let w1 = edge(p2.pos.x, p2.pos.y, p0.pos.x, p0.pos.y, px, py);
            let w2 = edge(p0.pos.x, p0.pos.y, p1.pos.x, p1.pos.y, px, py);
            let inside = |w: f32, o: bool| w > 0.0 || (w == 0.0 && o);
            if !(inside(w0, own[0]) && inside(w1, own[1]) && inside(w2, own[2])) {
                continue;
            }
            let (b0, b1, b2) = (w0 / area, w1 / area, w2 / area);
            let u = p0.uv.x * b0 + p1.uv.x * b1 + p2.uv.x * b2;
            let vv = p0.uv.y * b0 + p1.uv.y * b1 + p2.uv.y * b2;
            let t = sample(tex, u, vv);
            let ch = |i: usize| -> f32 {
                let c = |p: &egui::epaint::Vertex| match i {
                    0 => p.color.r(),
                    1 => p.color.g(),
                    2 => p.color.b(),
                    _ => p.color.a(),
                } as f32;
                c(&p0) * b0 + c(&p1) * b1 + c(&p2) * b2
            };
            // Both factors are premultiplied, 0..=255.
            let src = [
                ch(0) * t[0] / 255.0,
                ch(1) * t[1] / 255.0,
                ch(2) * t[2] / 255.0,
                ch(3) * t[3] / 255.0,
            ];
            let i = (y as usize * fw + x as usize) * 3;
            let keep = 1.0 - src[3] / 255.0;
            for k in 0..3 {
                let d = fb[i + k] as f32;
                fb[i + k] = (src[k] + d * keep).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

/// 24-bit BMP (bottom-up rows, 4-byte padded).
pub fn bmp(rgb: &[u8], w: usize, h: usize) -> Vec<u8> {
    let row = (w * 3).div_ceil(4) * 4;
    let size = 54 + row * h;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&(h as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&[0; 24]);
    for y in (0..h).rev() {
        let start = out.len();
        for x in 0..w {
            let i = (y * w + x) * 3;
            out.extend_from_slice(&[rgb[i + 2], rgb[i + 1], rgb[i]]);
        }
        out.resize(start + row, 0);
    }
    out
}
