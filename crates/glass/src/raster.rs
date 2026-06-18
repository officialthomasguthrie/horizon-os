// Software rasterization of a Glass `Scene` into an RGBA pixel buffer.
//
// This is the other half of the headless split: `surface::layout` turns the
// model into positioned primitives, and this turns those primitives into pixels,
// both pure and tested without a display. The compositor's only job on top is to
// upload this buffer as a texture and put it on a GPU; on a host with no screen
// the buffer can still be written to an image and looked at, so the surface is
// verifiable here, not only on hardware.
//
// Text is the legacy 8x8 bitmap font, each glyph 8 rows of 8 bits with the low
// bit leftmost, stamped at an integer scale.

use font8x8::legacy::BASIC_LEGACY;

use crate::surface::{Color, Primitive, Scene, GLYPH};

// An RGBA8 image, row-major, four bytes per pixel.
#[derive(Clone, Debug)]
pub struct Pixmap {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl Pixmap {
    // A new image filled with an opaque background.
    pub fn new(width: u32, height: u32, bg: Color) -> Pixmap {
        let mut rgba = vec![0u8; (width * height * 4) as usize];
        for px in rgba.chunks_exact_mut(4) {
            px[0] = bg.r;
            px[1] = bg.g;
            px[2] = bg.b;
            px[3] = 255;
        }
        Pixmap {
            width,
            height,
            rgba,
        }
    }

    // The pixel at (x, y). Out of bounds reads transparent black.
    pub fn pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.width || y >= self.height {
            return Color::rgba(0, 0, 0, 0);
        }
        let i = ((y * self.width + x) * 4) as usize;
        Color::rgba(
            self.rgba[i],
            self.rgba[i + 1],
            self.rgba[i + 2],
            self.rgba[i + 3],
        )
    }

    // Source-over blend of `c` onto the pixel at (x, y). The surface stays
    // opaque (it is composited onto a known background), so alpha only weights
    // the color and the stored alpha is left at full.
    fn blend(&mut self, x: i32, y: i32, c: Color) {
        if x < 0 || y < 0 || x as u32 >= self.width || y as u32 >= self.height {
            return;
        }
        let i = ((y as u32 * self.width + x as u32) * 4) as usize;
        if c.a == 255 {
            self.rgba[i] = c.r;
            self.rgba[i + 1] = c.g;
            self.rgba[i + 2] = c.b;
            self.rgba[i + 3] = 255;
            return;
        }
        let a = c.a as u32;
        let inv = 255 - a;
        let mix = |src: u8, dst: u8| ((src as u32 * a + dst as u32 * inv) / 255) as u8;
        self.rgba[i] = mix(c.r, self.rgba[i]);
        self.rgba[i + 1] = mix(c.g, self.rgba[i + 1]);
        self.rgba[i + 2] = mix(c.b, self.rgba[i + 2]);
        self.rgba[i + 3] = 255;
    }

    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: Color) {
        if c.a == 0 {
            return;
        }
        for yy in y..y + h {
            for xx in x..x + w {
                self.blend(xx, yy, c);
            }
        }
    }

    // Stamp one character's bitmap at (x, y), scaled, in color `c`.
    fn glyph(&mut self, ch: char, x: i32, y: i32, scale: i32, c: Color) {
        let code = ch as u32;
        let bitmap = if code < 128 {
            &BASIC_LEGACY[code as usize]
        } else {
            &BASIC_LEGACY['?' as usize]
        };
        for (row, bits) in bitmap.iter().enumerate() {
            for col in 0..8 {
                if bits & (1 << col) != 0 {
                    self.fill_rect(x + col * scale, y + row as i32 * scale, scale, scale, c);
                }
            }
        }
    }

    fn text(&mut self, s: &str, x: i32, y: i32, scale: i32, c: Color) {
        let mut cx = x;
        for ch in s.chars() {
            self.glyph(ch, cx, y, scale, c);
            cx += GLYPH * scale;
        }
    }
}

// Rasterize a scene to a fresh pixmap.
pub fn rasterize(scene: &Scene) -> Pixmap {
    let mut pm = Pixmap::new(
        scene.width.max(0) as u32,
        scene.height.max(0) as u32,
        scene.bg,
    );
    for prim in &scene.prims {
        match prim {
            Primitive::Rect { x, y, w, h, color } => pm.fill_rect(*x, *y, *w, *h, *color),
            Primitive::Text {
                x,
                y,
                scale,
                color,
                text,
            } => pm.text(text, *x, *y, *scale, *color),
        }
    }
    pm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface;

    #[test]
    fn fill_rect_paints_inside_and_leaves_outside() {
        let bg = Color::rgb(0, 0, 0);
        let red = Color::rgb(255, 0, 0);
        let scene = Scene {
            width: 10,
            height: 10,
            bg,
            prims: vec![Primitive::Rect {
                x: 2,
                y: 2,
                w: 3,
                h: 3,
                color: red,
            }],
            hits: vec![],
        };
        let pm = rasterize(&scene);
        assert_eq!(pm.pixel(3, 3), red);
        assert_eq!(pm.pixel(0, 0), Color::rgba(0, 0, 0, 255));
        // Just outside the rect (x in 2..5) stays background.
        assert_eq!(pm.pixel(5, 3), Color::rgba(0, 0, 0, 255));
    }

    #[test]
    fn rect_clips_to_bounds() {
        let scene = Scene {
            width: 4,
            height: 4,
            bg: Color::rgb(0, 0, 0),
            prims: vec![Primitive::Rect {
                x: -2,
                y: -2,
                w: 100,
                h: 100,
                color: Color::rgb(1, 2, 3),
            }],
            hits: vec![],
        };
        // Drawing far out of bounds must not panic and must fill what is in view.
        let pm = rasterize(&scene);
        assert_eq!(pm.pixel(0, 0), Color::rgb(1, 2, 3));
        assert_eq!(pm.pixel(3, 3), Color::rgb(1, 2, 3));
    }

    #[test]
    fn glyph_a_lights_its_known_pixels() {
        // 'A' row 0 is 0x0C: columns 2 and 3 set, others clear (low bit left).
        let fg = Color::rgb(200, 200, 200);
        let scene = Scene {
            width: 8,
            height: 8,
            bg: Color::rgb(0, 0, 0),
            prims: vec![Primitive::Text {
                x: 0,
                y: 0,
                scale: 1,
                color: fg,
                text: "A".into(),
            }],
            hits: vec![],
        };
        let pm = rasterize(&scene);
        assert_eq!(pm.pixel(2, 0), fg);
        assert_eq!(pm.pixel(3, 0), fg);
        assert_eq!(pm.pixel(0, 0), Color::rgba(0, 0, 0, 255));
        assert_eq!(pm.pixel(7, 0), Color::rgba(0, 0, 0, 255));
    }

    #[test]
    fn text_advances_one_cell_per_char() {
        // Two 'A's: the second lands 8 px right, so its lit columns are 10, 11.
        let fg = Color::rgb(200, 200, 200);
        let scene = Scene {
            width: 24,
            height: 8,
            bg: Color::rgb(0, 0, 0),
            prims: vec![Primitive::Text {
                x: 0,
                y: 0,
                scale: 1,
                color: fg,
                text: "AA".into(),
            }],
            hits: vec![],
        };
        let pm = rasterize(&scene);
        assert_eq!(pm.pixel(10, 0), fg);
        assert_eq!(pm.pixel(11, 0), fg);
    }

    #[test]
    fn half_alpha_blends_halfway() {
        let scene = Scene {
            width: 2,
            height: 2,
            bg: Color::rgb(0, 0, 0),
            prims: vec![Primitive::Rect {
                x: 0,
                y: 0,
                w: 2,
                h: 2,
                color: Color::rgba(255, 255, 255, 128),
            }],
            hits: vec![],
        };
        let pm = rasterize(&scene);
        let p = pm.pixel(0, 0);
        // 255 * 128 / 255 == 128, opaque result.
        assert_eq!((p.r, p.g, p.b, p.a), (128, 128, 128, 255));
    }

    #[test]
    fn a_live_model_rasterizes_with_a_green_pixel() {
        // End to end: a model with one live channel must paint at least one pixel
        // in the live color, proving layout and raster meet.
        let m = crate::tests_support::one_live_model();
        let scene = surface::layout(&m, 800, 400, 2);
        let pm = rasterize(&scene);
        assert_eq!(pm.width, 800);
        assert_eq!(pm.height, 400);
        let green = surface::LIVE;
        let found = pm
            .rgba
            .chunks_exact(4)
            .any(|px| px[0] == green.r && px[1] == green.g && px[2] == green.b);
        assert!(
            found,
            "expected a live-colored pixel in the rendered surface"
        );
    }
}
