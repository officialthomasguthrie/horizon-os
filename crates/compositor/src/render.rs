//! Software (pixman) offscreen compositing, and the shared paint path.
//!
//! This is the step that turns client buffers into pixels, kept on the same
//! split as the rest of the compositor: the part that can be proven without a
//! display is built and tested headlessly. [`paint_space`] imports each mapped
//! surface's buffer and composites the `Space` into a bound framebuffer; it is
//! generic over the renderer, so the same code paints the offscreen pixman
//! buffer asserted on in the headless test and the on-screen GLES window the
//! winit backend presents. Only the render target differs.
//!
//! [`render_space`] is the headless path: paint into an offscreen pixman buffer
//! (pure software, no GPU) and read the pixels back. Pixels come back as
//! `Argb8888` (the DRM fourcc): little-endian, four bytes per pixel, so a 32-bit
//! word reads `0xAARRGGBB`. [`RenderedFrame::argb`] decodes one pixel that way.

use smithay::backend::allocator::Fourcc;
use smithay::backend::renderer::element::surface::{
    render_elements_from_surface_tree, WaylandSurfaceRenderElement,
};
use smithay::backend::renderer::element::Kind;
use smithay::backend::renderer::utils::draw_render_elements;
use smithay::backend::renderer::{
    Bind, Color32F, ExportMem, Frame, ImportAll, Offscreen, Renderer,
};
use smithay::desktop::{Space, Window};
use smithay::output::Output;
use smithay::utils::{Buffer as BufferCoords, Physical, Rectangle, Size, Transform};

use crate::{Error, Result};

/// One composited frame, read back from the offscreen framebuffer. The bytes are
/// `Argb8888`: `width * height` pixels, four bytes each, little-endian.
pub struct RenderedFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl RenderedFrame {
    /// The pixel at `(x, y)` as `0xAARRGGBB`. Out-of-bounds reads return 0.
    pub fn argb(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        let i = ((y * self.width + x) * 4) as usize;
        u32::from_le_bytes([
            self.pixels[i],
            self.pixels[i + 1],
            self.pixels[i + 2],
            self.pixels[i + 3],
        ])
    }
}

// Build the scene's render elements: one surface tree per mapped toplevel, placed
// at its location in the Space, in front-to-back order. Generic over the renderer
// so every paint path shares it, the offscreen pixman buffer ([`paint_space`]),
// the on-screen GLES window (also `paint_space`), and the DRM/KMS scanout (which
// hands these straight to `DrmOutput::render_frame`). They all draw the same
// scene; only the render target differs. The elements own their textures
// (`TextureId: Clone + 'static`), so the renderer borrow is released on return.
pub(crate) fn space_render_elements<R>(
    renderer: &mut R,
    space: &Space<Window>,
) -> Vec<WaylandSurfaceRenderElement<R>>
where
    R: Renderer + ImportAll,
    R::TextureId: Clone + 'static,
{
    let mut elements: Vec<WaylandSurfaceRenderElement<R>> = Vec::new();
    for window in space.elements() {
        let Some(toplevel) = window.toplevel() else {
            continue;
        };
        let loc = space.element_location(window).unwrap_or_default();
        elements.extend(render_elements_from_surface_tree(
            renderer,
            toplevel.wl_surface(),
            (loc.x, loc.y),
            1.0,
            1.0,
            Kind::Unspecified,
        ));
    }
    elements
}

// Import every mapped surface's buffer and composite the scene into the bound
// framebuffer: clear to `clear`, then draw each window at its scene location.
// Generic over the renderer so the headless (pixman) and on-screen (GLES) paths
// run the same compositing. `transform` is the output transform the backend
// needs (none for a top-left offscreen buffer, a flip for a GL window). The
// DRM/KMS backend does not call this: its `DrmOutput` clears and draws the
// elements from [`space_render_elements`] itself.
pub(crate) fn paint_space<'buffer, R>(
    renderer: &mut R,
    framebuffer: &mut R::Framebuffer<'buffer>,
    space: &Space<Window>,
    size: Size<i32, Physical>,
    transform: Transform,
    clear: Color32F,
) -> Result<()>
where
    R: Renderer + ImportAll,
    R::TextureId: Clone + 'static,
{
    let elements = space_render_elements(renderer, space);

    let full = Rectangle::from_size(size);
    let mut frame = renderer
        .render(framebuffer, size, transform)
        .map_err(|e| Error::Render(e.to_string()))?;
    frame
        .clear(clear, &[full])
        .map_err(|e| Error::Render(e.to_string()))?;
    draw_render_elements(&mut frame, 1.0, &elements, &[full])
        .map_err(|e| Error::Render(e.to_string()))?;
    // The returned sync point is awaited by the caller's present (winit) or is
    // already signalled for synchronous software rendering (pixman).
    let _sync = frame.finish().map_err(|e| Error::Render(e.to_string()))?;
    Ok(())
}

// Composite the current scene into an offscreen Argb8888 buffer the size of the
// output, then read it back. A fresh renderer per call keeps this self-contained
// (the buffer import is a memcpy, cheap enough for the offscreen path); the
// on-screen backend holds its renderer across frames instead.
pub(crate) fn render_space(space: &Space<Window>, output: &Output) -> Result<RenderedFrame> {
    use smithay::backend::renderer::pixman::PixmanRenderer;

    let mode = output
        .current_mode()
        .ok_or_else(|| Error::Render("output has no mode".into()))?;
    let size = mode.size; // physical pixels

    let mut renderer = PixmanRenderer::new().map_err(|e| Error::Render(e.to_string()))?;
    let buffer_size = Size::<i32, BufferCoords>::from((size.w, size.h));
    let mut target = renderer
        .create_buffer(Fourcc::Argb8888, buffer_size)
        .map_err(|e| Error::Render(e.to_string()))?;

    let mut framebuffer = renderer
        .bind(&mut target)
        .map_err(|e| Error::Render(e.to_string()))?;
    // Top-left origin (no GL flip), so a readback pixel maps straight to its
    // scene coordinate. Clear to opaque black, then draw the windows over it.
    paint_space(
        &mut renderer,
        &mut framebuffer,
        space,
        size,
        Transform::Normal,
        Color32F::new(0.0, 0.0, 0.0, 1.0),
    )?;

    let region = Rectangle::from_size(buffer_size);
    let mapping = renderer
        .copy_framebuffer(&framebuffer, region, Fourcc::Argb8888)
        .map_err(|e| Error::Render(e.to_string()))?;
    let bytes = renderer
        .map_texture(&mapping)
        .map_err(|e| Error::Render(e.to_string()))?;

    Ok(RenderedFrame {
        width: size.w as u32,
        height: size.h as u32,
        pixels: bytes.to_vec(),
    })
}
