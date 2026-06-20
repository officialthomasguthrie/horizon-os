//! Software (pixman) offscreen compositing, and the shared paint path.
//!
//! This is the step that turns client buffers into pixels, kept on the same
//! split as the rest of the compositor: the part that can be proven without a
//! display is built and tested headlessly. [`composite`] is the core that imports
//! the scene's buffers and draws them (with the shell background behind) into a
//! bound framebuffer; it is generic over the renderer, so the same code paints the
//! offscreen pixman buffer asserted on in the headless tests and the on-screen
//! GLES window the winit backend presents ([`paint_space`]). Only the render
//! target differs.
//!
//! Which windows it draws depends on the element collector the caller picks: the
//! whole space from the global origin ([`space_render_elements`], the single-output
//! winit and [`render_space`] paths) or one output's own region of the shared
//! logical space ([`output_render_elements`], the multi-monitor [`render_output`]
//! path and the DRM scanout). [`render_space`] and [`render_output`] are the
//! headless readbacks: paint into an offscreen pixman buffer (pure software, no
//! GPU) and read the pixels back. Pixels come back as `Argb8888` (the DRM fourcc):
//! little-endian, four bytes per pixel, so a 32-bit word reads `0xAARRGGBB`.
//! [`RenderedFrame::argb`] decodes one pixel that way.

use smithay::backend::allocator::Fourcc;
use smithay::backend::renderer::element::surface::{
    render_elements_from_surface_tree, WaylandSurfaceRenderElement,
};
use smithay::backend::renderer::element::Kind;
use smithay::backend::renderer::utils::draw_render_elements;
use smithay::backend::renderer::{
    Bind, Color32F, ExportMem, Frame, ImportAll, ImportMem, Offscreen, Renderer, Texture,
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

/// The shell background: a full-screen RGBA image drawn behind every client
/// window (Horizon paints the Glass home surface here). Held as raw bytes the
/// renderer uploads each frame, so it stays independent of any one renderer's
/// texture type (in particular the pixman texture is not `Send`, which rules out
/// the cached buffer element). The bytes are `width * height` pixels, four each,
/// in the `Abgr8888` order `glass::Pixmap` produces (R, G, B, A).
#[derive(Clone)]
pub struct ShellBackground {
    rgba: Vec<u8>,
    width: i32,
    height: i32,
}

impl ShellBackground {
    pub fn new(rgba: Vec<u8>, width: i32, height: i32) -> ShellBackground {
        ShellBackground {
            rgba,
            width,
            height,
        }
    }

    // The raw bytes and size, for the DRM backend to rebuild a `MemoryRenderBuffer`
    // (its element-list present loop cannot draw the texture directly the way
    // `paint_space` does). The winit and pixman paths read the fields directly.
    #[cfg(feature = "udev")]
    pub(crate) fn rgba(&self) -> &[u8] {
        &self.rgba
    }

    #[cfg(feature = "udev")]
    pub(crate) fn width(&self) -> i32 {
        self.width
    }

    #[cfg(feature = "udev")]
    pub(crate) fn height(&self) -> i32 {
        self.height
    }
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

// Build the whole scene's render elements: one surface tree per mapped toplevel,
// placed at its location in the Space, in front-to-back order, all from the global
// origin. This is the single-output collector: the winit nested window (via
// [`paint_space`]) and the headless [`render_space`] readback, where the one output
// sits at the origin. Multi-monitor paths use [`output_render_elements`] to take
// just one output's region instead. Generic over the renderer so each path shares
// it; the elements own their textures (`TextureId: Clone + 'static`), so the
// renderer borrow is released on return.
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

// The scene's render elements for one output's region of the shared logical
// space: only the windows that fall on this output, each offset so the output's
// logical origin maps to the framebuffer origin. This is what makes a real
// multi-monitor layout: every output paints its own slice instead of mirroring
// the whole scene from the global origin. The output must be mapped into the
// `Space` (so it has a geometry); an unmapped one yields nothing. Smithay's
// `render_elements_for_region` does the cropping and offset, so both the headless
// per-output readback ([`render_output`]) and the DRM scanout share it, the same
// way [`space_render_elements`] is shared by the single-output paths.
pub(crate) fn output_render_elements<R>(
    renderer: &mut R,
    space: &Space<Window>,
    output: &Output,
) -> Vec<WaylandSurfaceRenderElement<R>>
where
    R: Renderer + ImportAll,
    R::TextureId: Clone + Texture + 'static,
{
    match space.output_geometry(output) {
        Some(geo) => {
            let scale = output.current_scale().fractional_scale();
            space.render_elements_for_region(renderer, &geo, scale, 1.0)
        }
        None => Vec::new(),
    }
}

// How to paint one frame, distinct from its content (the elements and the
// background): the target's physical size, the output scale the elements were
// built at, the output transform, and the clear colour. `scale` matters because a
// surface element is sized by the scale it is drawn with, so it must match the
// scale the collector built the elements at, else a HiDPI window would size wrong;
// it is 1 for the single-output paths and the output's own scale for the
// per-output one.
struct FrameTarget {
    size: Size<i32, Physical>,
    scale: f64,
    transform: Transform,
    clear: Color32F,
}

// Composite a precomputed element list into the bound framebuffer: clear to the
// target's colour, draw the shell background behind everything, then the windows
// over it. Generic over the renderer so the headless (pixman) and on-screen (GLES)
// paths run the same compositing. The target's transform is the output transform
// the backend needs (none for a top-left offscreen buffer, a flip for a GL
// window). The elements are passed in so the caller chooses the scene: the whole
// space from the origin ([`space_render_elements`], the single-output paths) or
// one output's region ([`output_render_elements`], multi-monitor). The DRM/KMS
// backend does not call this: its `DrmOutput` clears and draws its own element
// list.
fn composite<'buffer, R>(
    renderer: &mut R,
    framebuffer: &mut R::Framebuffer<'buffer>,
    elements: &[WaylandSurfaceRenderElement<R>],
    target: &FrameTarget,
    background: Option<&ShellBackground>,
) -> Result<()>
where
    R: Renderer + ImportAll + ImportMem,
    R::TextureId: Clone + 'static,
{
    // Upload the background image to a texture before the frame borrows the
    // renderer. The window elements draw over it.
    let bg = match background {
        Some(b) => Some(
            renderer
                .import_memory(
                    &b.rgba,
                    Fourcc::Abgr8888,
                    Size::<i32, BufferCoords>::from((b.width, b.height)),
                    false,
                )
                .map_err(|e| Error::Render(e.to_string()))?,
        ),
        None => None,
    };

    let full = Rectangle::from_size(target.size);
    let mut frame = renderer
        .render(framebuffer, target.size, target.transform)
        .map_err(|e| Error::Render(e.to_string()))?;
    frame
        .clear(target.clear, &[full])
        .map_err(|e| Error::Render(e.to_string()))?;
    // The background sits behind the windows: drawn first, into the cleared
    // frame, with the buffer in its natural (top-left) orientation; the frame's
    // own transform handles any output flip.
    if let Some(tex) = &bg {
        frame
            .render_texture_at(
                tex,
                (0, 0).into(),
                1,
                1.0,
                Transform::Normal,
                &[full],
                &[],
                1.0,
            )
            .map_err(|e| Error::Render(e.to_string()))?;
    }
    draw_render_elements(&mut frame, target.scale, elements, &[full])
        .map_err(|e| Error::Render(e.to_string()))?;
    // The returned sync point is awaited by the caller's present (winit) or is
    // already signalled for synchronous software rendering (pixman).
    let _sync = frame.finish().map_err(|e| Error::Render(e.to_string()))?;
    Ok(())
}

// Composite the whole space (every window from the global origin) into the bound
// framebuffer, for the winit nested window: it presents one output (the default,
// at the origin), so the whole scene and its region coincide. The headless
// readback and the DRM scanout pick their elements per output instead.
#[cfg(feature = "winit")]
pub(crate) fn paint_space<'buffer, R>(
    renderer: &mut R,
    framebuffer: &mut R::Framebuffer<'buffer>,
    space: &Space<Window>,
    size: Size<i32, Physical>,
    transform: Transform,
    clear: Color32F,
    background: Option<&ShellBackground>,
) -> Result<()>
where
    R: Renderer + ImportAll + ImportMem,
    R::TextureId: Clone + 'static,
{
    let elements = space_render_elements(renderer, space);
    // The nested window presents the default output at scale 1, matching the scale
    // the whole-space elements are built at.
    let target = FrameTarget {
        size,
        scale: 1.0,
        transform,
        clear,
    };
    composite(renderer, framebuffer, &elements, &target, background)
}

// Composite an offscreen Argb8888 buffer of `size` and read it back, the headless
// software path. A fresh pixman renderer per call keeps this self-contained (the
// buffer import is a memcpy, cheap enough for the offscreen path); the on-screen
// backend holds its renderer across frames instead. The caller supplies the scene
// as a closure over the renderer, so the same readback serves the whole-space and
// per-output element collectors, and `scale` (the output scale the closure built
// the elements at) is forwarded to the draw so a HiDPI output's window is sized to
// match. Pixels come back top-left origin (no GL flip), so a readback pixel maps
// straight to its scene coordinate.
fn read_back<F>(
    size: Size<i32, Physical>,
    scale: f64,
    background: Option<&ShellBackground>,
    scene: F,
) -> Result<RenderedFrame>
where
    F: FnOnce(
        &mut smithay::backend::renderer::pixman::PixmanRenderer,
    ) -> Vec<
        WaylandSurfaceRenderElement<smithay::backend::renderer::pixman::PixmanRenderer>,
    >,
{
    use smithay::backend::renderer::pixman::PixmanRenderer;

    let mut renderer = PixmanRenderer::new().map_err(|e| Error::Render(e.to_string()))?;
    // The elements own their textures, so building them here releases the
    // renderer borrow before the frame binds it.
    let elements = scene(&mut renderer);

    let buffer_size = Size::<i32, BufferCoords>::from((size.w, size.h));
    let mut target = renderer
        .create_buffer(Fourcc::Argb8888, buffer_size)
        .map_err(|e| Error::Render(e.to_string()))?;
    let mut framebuffer = renderer
        .bind(&mut target)
        .map_err(|e| Error::Render(e.to_string()))?;
    let target = FrameTarget {
        size,
        scale,
        transform: Transform::Normal,
        clear: Color32F::new(0.0, 0.0, 0.0, 1.0),
    };
    composite(
        &mut renderer,
        &mut framebuffer,
        &elements,
        &target,
        background,
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

// The physical pixel size of an output's current mode, or an error if it has none.
fn output_size(output: &Output) -> Result<Size<i32, Physical>> {
    output
        .current_mode()
        .map(|m| m.size)
        .ok_or_else(|| Error::Render("output has no mode".into()))
}

// Composite the whole space into an offscreen buffer the size of the output and
// read it back: the headless single-output path behind `Compositor::render`.
pub(crate) fn render_space(
    space: &Space<Window>,
    output: &Output,
    background: Option<&ShellBackground>,
) -> Result<RenderedFrame> {
    // The whole-space collector builds elements at scale 1, so draw at 1 too; this
    // path serves the default output, which is always scale 1.
    read_back(output_size(output)?, 1.0, background, |renderer| {
        space_render_elements(renderer, space)
    })
}

// Composite one output's own region of the shared space into an offscreen buffer
// the size of that output's mode and read it back: the headless multi-monitor
// path behind `Compositor::render_output`. The output must be mapped into the
// space; an unmapped one renders an empty (cleared) frame. This exercises the
// exact `output_render_elements` the DRM backend scans out, so per-output region
// rendering is proven without a display, the same split the rest of the
// compositor uses.
pub(crate) fn render_output(
    space: &Space<Window>,
    output: &Output,
    background: Option<&ShellBackground>,
) -> Result<RenderedFrame> {
    // The per-output collector builds elements at this output's scale, so the draw
    // must use the same scale or a HiDPI window would be sized wrong.
    let scale = output.current_scale().fractional_scale();
    read_back(output_size(output)?, scale, background, |renderer| {
        output_render_elements(renderer, space, output)
    })
}
