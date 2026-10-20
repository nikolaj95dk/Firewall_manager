//! Procedurally rendered app icon (rounded gradient tile with a shield and check mark).
//! Shared between `build.rs` (to produce the .ico embedded in the exe) and the app
//! (window / taskbar icon), so both always match.

const SUBSAMPLES: u32 = 4;

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

fn shield_polygon() -> Vec<(f32, f32)> {
    let mut pts = Vec::new();
    // Right half: top peak -> right shoulder -> right side -> curve to bottom point.
    pts.push((0.5, 0.15));
    pts.push((0.745, 0.245));
    pts.push((0.745, 0.47));
    let (p0, c, p1) = ((0.745, 0.47), (0.735, 0.72), (0.5, 0.875));
    for i in 1..=24 {
        let t = i as f32 / 24.0;
        let x = (1.0 - t) * (1.0 - t) * p0.0 + 2.0 * (1.0 - t) * t * c.0 + t * t * p1.0;
        let y = (1.0 - t) * (1.0 - t) * p0.1 + 2.0 * (1.0 - t) * t * c.1 + t * t * p1.1;
        pts.push((x, y));
    }
    // Mirror for the left half (walk back up).
    let right: Vec<_> = pts.clone();
    for &(x, y) in right.iter().rev().skip(1) {
        if (x - 0.5).abs() > 1e-4 {
            pts.push((1.0 - x, y));
        }
    }
    pts
}

fn inside_polygon(poly: &[(f32, f32)], x: f32, y: f32) -> bool {
    let mut inside = false;
    let mut j = poly.len() - 1;
    for i in 0..poly.len() {
        let (xi, yi) = poly[i];
        let (xj, yj) = poly[j];
        if (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn dist_to_segment(px: f32, py: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let t = (((px - a.0) * dx + (py - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    let (cx, cy) = (a.0 + dx * t, a.1 + dy * t);
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

fn inside_rounded_rect(x: f32, y: f32, margin: f32, radius: f32) -> bool {
    let (lo, hi) = (margin, 1.0 - margin);
    if x < lo || x > hi || y < lo || y > hi {
        return false;
    }
    let cx = x.clamp(lo + radius, hi - radius);
    let cy = y.clamp(lo + radius, hi - radius);
    (x - cx).powi(2) + (y - cy).powi(2) <= radius * radius
}

/// Renders the icon as straight (non-premultiplied) RGBA8, `size * size * 4` bytes.
pub fn render(size: u32) -> Vec<u8> {
    let shield = shield_polygon();
    let check = [(0.385, 0.505), (0.47, 0.595), (0.625, 0.42)];
    let check_half_width = 0.052;

    // Gradient endpoints: soft indigo -> violet.
    let c0 = (99.0, 132.0, 255.0);
    let c1 = (157.0, 108.0, 247.0);

    let mut out = vec![0u8; (size * size * 4) as usize];
    let n = SUBSAMPLES * SUBSAMPLES;
    for py in 0..size {
        for px in 0..size {
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SUBSAMPLES {
                for sx in 0..SUBSAMPLES {
                    let x = (px as f32 + (sx as f32 + 0.5) / SUBSAMPLES as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SUBSAMPLES as f32) / size as f32;
                    if !inside_rounded_rect(x, y, 0.03, 0.22) {
                        continue;
                    }
                    let t = ((x + y) * 0.5).clamp(0.0, 1.0);
                    let bg = (lerp(c0.0, c1.0, t), lerp(c0.1, c1.1, t), lerp(c0.2, c1.2, t));
                    let in_check = dist_to_segment(x, y, check[0], check[1]) < check_half_width
                        || dist_to_segment(x, y, check[1], check[2]) < check_half_width;
                    let col = if inside_polygon(&shield, x, y) && !in_check {
                        // Shield: near-white with a faint vertical shade.
                        let s = lerp(255.0, 226.0, ((y - 0.15) / 0.75).clamp(0.0, 1.0));
                        (s, s, (s + 8.0).min(255.0))
                    } else {
                        bg
                    };
                    r += col.0;
                    g += col.1;
                    b += col.2;
                    a += 1.0;
                }
            }
            let i = ((py * size + px) * 4) as usize;
            if a > 0.0 {
                out[i] = (r / a) as u8;
                out[i + 1] = (g / a) as u8;
                out[i + 2] = (b / a) as u8;
                out[i + 3] = ((a / n as f32) * 255.0).round() as u8;
            }
        }
    }
    out
}
