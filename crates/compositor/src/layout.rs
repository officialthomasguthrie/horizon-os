//! Logical output layout: where each connected output sits in the one shared
//! desktop coordinate space.
//!
//! Without a layout every output mirrors the whole scene from the origin, so two
//! monitors show the same pixels. A real layout instead gives every output its
//! own region of one coordinate space, so a window lives at a single position
//! across the whole desktop and each output paints only the part it covers.
//!
//! The policy is the common default: outputs laid left to right in the order
//! given, each at the top (`y = 0`), the next starting where the previous one
//! ended. It is a pure function of the output sizes, so it is unit-tested with no
//! display, the same split the rest of the compositor uses; the DRM backend feeds
//! it the real connected modes and maps each output into the `Space` at the
//! position it returns. Plain integers, no Wayland types, so this builds and
//! tests on every host, not only Linux.

/// Logical positions for `sizes`, laid left to right and top-aligned. Each entry
/// is a `(width, height)` in logical pixels, in the order the outputs should
/// appear; the returned `(x, y)` at index `i` is where output `i` goes. The first
/// sits at the origin and each next one starts at the right edge of those before
/// it. A non-positive width adds no advance (it stacks at the current `x`), so a
/// bogus mode cannot drag later outputs off into negative space.
pub fn arrange(sizes: &[(i32, i32)]) -> Vec<(i32, i32)> {
    let mut positions = Vec::with_capacity(sizes.len());
    let mut x = 0;
    for &(w, _) in sizes {
        positions.push((x, 0));
        x += w.max(0);
    }
    positions
}

/// The bounding size `(width, height)` of the whole desktop the [`arrange`]d
/// outputs span: the sum of the widths and the tallest height. This is the box a
/// cursor roams over a multi-monitor desktop, so the pointer can cross from one
/// screen to the next instead of being trapped on the first. Empty input spans
/// nothing.
pub fn span(sizes: &[(i32, i32)]) -> (i32, i32) {
    let width = sizes.iter().map(|&(w, _)| w.max(0)).sum();
    let height = sizes.iter().map(|&(_, h)| h.max(0)).max().unwrap_or(0);
    (width, height)
}

// The pixel density at or above which a monitor is treated as HiDPI and given an
// integer scale of 2. Roughly double the classic 96 DPI desktop baseline, the
// same line mutter has used to auto-pick 2x.
const HIDPI_DPI: f64 = 192.0;

/// The integer output scale to advertise for a monitor whose current mode is
/// `mode` pixels on a panel measuring `physical_mm`, a simple density heuristic:
/// 2 for a high-density panel, 1 otherwise. The scale divides the physical mode
/// into the logical size the desktop lays out in (a 3840x2160 panel at scale 2
/// occupies 1920x1080 of logical space) and is what a client reads from
/// `wl_output.scale` to render crisply.
///
/// A non-positive mode or an unknown physical size (a monitor that reports no
/// EDID dimensions, common enough) cannot be reasoned about, so it stays at 1
/// rather than guess. Only integer scales are derived: the 150-190 DPI middle
/// ground (a 27-inch 4K, say) really wants fractional scaling, which needs the
/// fractional-scale protocol and is a later refinement. Pure integer-and-float
/// math, no Wayland types, so the DRM backend's per-connector choice is
/// unit-tested with no display, like the rest of this module.
pub fn scale_for(mode: (i32, i32), physical_mm: (i32, i32)) -> i32 {
    let (w, h) = mode;
    let (mm_w, mm_h) = physical_mm;
    if w <= 0 || h <= 0 || mm_w <= 0 || mm_h <= 0 {
        return 1;
    }
    // Density along the diagonal, so the ratio is independent of aspect.
    let px_diag = ((w as f64).powi(2) + (h as f64).powi(2)).sqrt();
    let in_diag = ((mm_w as f64).powi(2) + (mm_h as f64).powi(2)).sqrt() / 25.4;
    let dpi = px_diag / in_diag;
    if dpi >= HIDPI_DPI {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spans_nothing() {
        assert_eq!(arrange(&[]), Vec::<(i32, i32)>::new());
        assert_eq!(span(&[]), (0, 0));
    }

    #[test]
    fn single_output_sits_at_the_origin() {
        assert_eq!(arrange(&[(1920, 1080)]), vec![(0, 0)]);
        assert_eq!(span(&[(1920, 1080)]), (1920, 1080));
    }

    #[test]
    fn outputs_stack_left_to_right() {
        let sizes = [(1920, 1080), (1280, 1024), (800, 600)];
        assert_eq!(arrange(&sizes), vec![(0, 0), (1920, 0), (3200, 0)]);
        // Width is the sum, height is the tallest.
        assert_eq!(span(&sizes), (4000, 1080));
    }

    #[test]
    fn differing_heights_stay_top_aligned() {
        // Every output is pinned to y = 0 regardless of height.
        let sizes = [(800, 600), (800, 1200)];
        assert_eq!(arrange(&sizes), vec![(0, 0), (800, 0)]);
        assert_eq!(span(&sizes), (1600, 1200));
    }

    #[test]
    fn a_bogus_width_does_not_advance_later_outputs() {
        // A zero or negative width contributes no horizontal advance, so the
        // next real output still lands at a sane position rather than overlapping
        // off to the left.
        let sizes = [(0, 0), (1024, 768)];
        assert_eq!(arrange(&sizes), vec![(0, 0), (0, 0)]);
        assert_eq!(span(&sizes), (1024, 768));
    }

    #[test]
    fn ordinary_desktop_monitors_stay_at_scale_1() {
        // 1080p on a 24-inch panel (~92 DPI) and 1440p on a 27-inch (~109 DPI):
        // both well under the HiDPI line.
        assert_eq!(scale_for((1920, 1080), (531, 299)), 1);
        assert_eq!(scale_for((2560, 1440), (597, 336)), 1);
    }

    #[test]
    fn high_density_panels_get_scale_2() {
        // A 4K 15.6-inch laptop panel (~283 DPI) and a 5K 27-inch (~218 DPI).
        assert_eq!(scale_for((3840, 2160), (344, 194)), 2);
        assert_eq!(scale_for((5120, 2880), (597, 336)), 2);
    }

    #[test]
    fn a_27_inch_4k_stays_integer_1_until_fractional_scaling() {
        // ~163 DPI sits in the middle ground that wants 1.5x; with only integer
        // scales derived it stays 1 rather than jumping to a too-large 2.
        assert_eq!(scale_for((3840, 2160), (597, 336)), 1);
    }

    #[test]
    fn an_unknown_physical_size_stays_at_scale_1() {
        // A monitor that reports no EDID dimensions cannot have its density
        // computed, so it is left at 1 rather than guessed.
        assert_eq!(scale_for((3840, 2160), (0, 0)), 1);
        assert_eq!(scale_for((0, 0), (340, 190)), 1);
    }
}
