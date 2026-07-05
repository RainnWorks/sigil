//! Self-contained QR rendering: a terminal picture, a scannable PNG, and an SVG,
//! from one module matrix.
//!
//! The `qrcode` crate is pulled with `default-features = false`, so its `image`
//! and `svg` render backends (and the whole `image` dependency stack) never
//! enter the single binary. This module supplies its own renderers instead:
//! unicode half-blocks for the terminal, and a from-scratch PNG encoder (grayscale,
//! DEFLATE *stored* blocks, hand-computed CRC-32 and Adler-32) so a `latch qr
//! --png` writes a real, scannable image with no compression dependency.
//!
//! Two invariants make the output actually scan:
//! - Error correction is fixed at [`EcLevel::Q`] (~25% recovery) so a printed or
//!   photographed code survives smudging and glare.
//! - Every rendering carries a [`QUIET_ZONE`] of 4 light modules on all sides,
//!   the minimum the QR spec requires for a camera to lock on. We add the margin
//!   ourselves rather than trusting a backend default, so it is uniform across
//!   the terminal, PNG, and SVG paths and can be asserted in tests.

use std::path::Path;

use anyhow::{Context, Result};
use qrcode::{Color, EcLevel, QrCode};

/// Light-module margin on every side, in modules. Four is the QR-spec minimum
/// for reliable acquisition; we never render below it.
pub const QUIET_ZONE: usize = 4;

/// Encode `data` into a square module matrix at error-correction level Q.
///
/// Returns `(n, dark)` where `n` is the side length in modules and `dark` is the
/// row-major grid (`dark[y * n + x]`, `true` = a dark module). The quiet zone is
/// *not* included here; each renderer adds [`QUIET_ZONE`] around this core.
fn encode(data: &str) -> Result<(usize, Vec<bool>)> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::Q)
        .context("encoding the QR (payload too large for a single symbol?)")?;
    let n = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == Color::Dark)
        .collect();
    Ok((n, dark))
}

/// Render `data` as a terminal QR using unicode half-blocks (`█ ▀ ▄` and space),
/// packing two module rows into each character row, framed by a [`QUIET_ZONE`]
/// white margin.
///
/// Dark modules render as the terminal's foreground color, so the result scans as
/// dark-on-light on a light terminal (a dark-terminal user can invert their
/// colors, exactly as a printed code on white paper expects).
pub fn render_terminal(data: &str) -> Result<String> {
    let (n, dark) = encode(data)?;
    let n = n as isize;
    let q = QUIET_ZONE as isize;
    // A module outside the code proper is quiet zone: light.
    let at = |x: isize, y: isize| -> bool {
        if x < 0 || y < 0 || x >= n || y >= n {
            false
        } else {
            dark[(y * n + x) as usize]
        }
    };
    let mut out = String::new();
    let mut y = -q;
    while y < n + q {
        for x in -q..n + q {
            let top = at(x, y);
            let bottom = at(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',  // full block
                (true, false) => '\u{2580}', // upper half
                (false, true) => '\u{2584}', // lower half
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

/// Render `data` as an SVG string: a white background with one black rect per
/// dark module, `scale` pixels to a module, framed by the [`QUIET_ZONE`]. `scale`
/// is clamped to at least 1.
pub fn render_svg(data: &str, scale: u32) -> Result<String> {
    let (n, dark) = encode(data)?;
    let scale = scale.max(1);
    let modules = (n + 2 * QUIET_ZONE) as u32;
    let side = modules * scale;
    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{side}\" height=\"{side}\" \
         viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\">"
    ));
    svg.push_str(&format!(
        "<rect width=\"{side}\" height=\"{side}\" fill=\"#ffffff\"/>"
    ));
    for y in 0..n {
        for x in 0..n {
            if dark[y * n + x] {
                let px = (x + QUIET_ZONE) as u32 * scale;
                let py = (y + QUIET_ZONE) as u32 * scale;
                svg.push_str(&format!(
                    "<rect x=\"{px}\" y=\"{py}\" width=\"{scale}\" height=\"{scale}\"/>"
                ));
            }
        }
    }
    svg.push_str("</svg>");
    Ok(svg)
}

/// Encode `data` and write it as a grayscale PNG to `path`, `scale` pixels to a
/// module, framed by the [`QUIET_ZONE`]. `scale` is clamped to at least 1. The
/// image side is `(n + 2 * QUIET_ZONE) * scale` pixels.
pub fn write_png(data: &str, path: &Path, scale: u32) -> Result<()> {
    let png = encode_png(data, scale)?;
    std::fs::write(path, png).with_context(|| format!("writing QR PNG to {}", path.display()))?;
    Ok(())
}

/// The pixel side length `write_png` would produce for `data` at `scale`. Shared
/// by the CLI's confirmation line and the PNG tests.
pub fn png_side_px(data: &str, scale: u32) -> Result<u32> {
    let (n, _) = encode(data)?;
    Ok((n as u32 + 2 * QUIET_ZONE as u32) * scale.max(1))
}

/// Build the PNG bytes: 8-bit grayscale (0 = black module, 255 = light),
/// filter-None scanlines, wrapped in a minimal zlib stream of DEFLATE stored
/// blocks. No compression crate: a QR is tiny and stored blocks decode everywhere.
fn encode_png(data: &str, scale: u32) -> Result<Vec<u8>> {
    let (n, dark) = encode(data)?;
    let scale = scale.max(1) as usize;
    let side = (n + 2 * QUIET_ZONE) * scale;

    // Raw image: each row is a filter byte (0 = None) followed by one gray byte
    // per pixel. A pixel is dark iff its module (after removing the quiet-zone
    // offset and the scale factor) is a dark module.
    let mut raw = Vec::with_capacity(side * (side + 1));
    for py in 0..side {
        raw.push(0u8);
        let my = py / scale;
        for pixel in 0..side {
            let mx = pixel / scale;
            let is_dark = mx >= QUIET_ZONE
                && mx < QUIET_ZONE + n
                && my >= QUIET_ZONE
                && my < QUIET_ZONE + n
                && dark[(my - QUIET_ZONE) * n + (mx - QUIET_ZONE)];
            raw.push(if is_dark { 0 } else { 255 });
        }
    }

    let side = side as u32;
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&side.to_be_bytes());
    ihdr.extend_from_slice(&side.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // color type: grayscale
    ihdr.push(0); // compression: deflate
    ihdr.push(0); // filter method: adaptive (per-line filter byte)
    ihdr.push(0); // interlace: none
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    png_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

/// Append a length-prefixed, CRC-checked PNG chunk.
fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
}

/// Wrap `data` in a zlib stream of uncompressed DEFLATE stored blocks (max 65535
/// bytes each), terminated by the required Adler-32 checksum.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 16);
    out.push(0x78); // CMF: deflate, 32K window
    out.push(0x01); // FLG: no dict, fastest; 0x7801 is a multiple of 31
    let mut i = 0;
    loop {
        let chunk = (data.len() - i).min(65535);
        let is_final = i + chunk >= data.len();
        out.push(u8::from(is_final)); // BFINAL bit, BTYPE = 00 (stored)
        let len = chunk as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&data[i..i + chunk]);
        i += chunk;
        if is_final {
            break;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// CRC-32 (IEEE 802.3, the PNG chunk polynomial) over a sequence of byte slices.
fn crc32(slices: &[&[u8]]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for slice in slices {
        for &byte in *slice {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }
    !crc
}

/// Adler-32 checksum, as required to close a zlib stream.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The symbol version (and therefore the module side) grows with the payload:
    /// a long string needs a larger QR than a short one.
    #[test]
    fn module_side_scales_with_input_length() {
        let (small, _) = encode("hi").unwrap();
        let (large, _) = encode(&"LATCH-PAIRING-PAYLOAD-".repeat(20)).unwrap();
        assert!(small >= 21, "smallest QR is version 1 (21 modules)");
        assert!(
            large > small,
            "a longer payload must need a larger symbol: {large} vs {small}"
        );
        // Every QR side is 4*version + 17, i.e. 21, 25, 29, ...
        assert_eq!((small - 17) % 4, 0, "side must be 4*version + 17");
    }

    /// The terminal render is made of half-block glyphs and carries the quiet
    /// zone: every line begins with at least QUIET_ZONE light (space) columns,
    /// and the whole first row is blank margin.
    #[test]
    fn terminal_render_has_block_glyphs_and_quiet_zone() {
        let art = render_terminal("LATCH-QR-TEST-payload-123").unwrap();
        assert!(
            art.contains('\u{2588}') || art.contains('\u{2580}') || art.contains('\u{2584}'),
            "terminal QR must use half-block glyphs"
        );
        let lines: Vec<&str> = art.lines().collect();
        assert!(lines.len() > QUIET_ZONE);
        for line in &lines {
            let margin: String = line.chars().take(QUIET_ZONE).collect();
            assert_eq!(
                margin,
                " ".repeat(QUIET_ZONE),
                "each line must open with a {QUIET_ZONE}-module light margin"
            );
        }
        // The top quiet zone (4 light module rows) is two blank character rows.
        assert!(
            lines[0].trim().is_empty(),
            "the first row must be all quiet-zone margin"
        );
    }

    /// The PNG is a real file: valid signature, non-empty, and its IHDR reports
    /// exactly (n + 2*quiet) * scale pixels on each side.
    #[test]
    fn png_is_written_with_expected_dimensions() {
        let data = "LATCH-PNG-TEST-payload";
        let scale = 6u32;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("latch-qr-test-{}.png", std::process::id()));
        write_png(data, &path, scale).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(bytes.len() > 100, "a real PNG is not a stub");
        assert_eq!(
            &bytes[..8],
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
            "PNG signature"
        );
        // IHDR width/height: 8-byte sig + 4 len + 4 "IHDR", then two BE u32s.
        let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let expected = png_side_px(data, scale).unwrap();
        assert_eq!(width, expected);
        assert_eq!(height, expected);
        assert!(expected > 0);
    }

    /// The SVG carries the viewBox for the padded (quiet-zone-framed) side and at
    /// least one dark module rect.
    #[test]
    fn svg_has_padded_viewbox_and_modules() {
        let svg = render_svg("LATCH-SVG-TEST", 8).unwrap();
        let side = png_side_px("LATCH-SVG-TEST", 8).unwrap();
        assert!(svg.contains(&format!("viewBox=\"0 0 {side} {side}\"")));
        assert!(svg.contains("<rect"));
        assert!(svg.ends_with("</svg>"));
    }

    /// CRC-32 and Adler-32 match known vectors, so the PNG framing is correct.
    #[test]
    fn checksums_match_known_vectors() {
        // CRC-32 of the ASCII "IEND" chunk type with empty data is a PNG constant.
        assert_eq!(crc32(&[b"IEND", b""]), 0xae42_6082);
        // Adler-32 of "Wikipedia" is the canonical example value.
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }
}
