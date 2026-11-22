//! Stateless PNG export of the very same styled Frame used by the console.
use super::{Frame, Tone};
use anyhow::{Context, Result, ensure};
use std::{mem::size_of, path::Path, ptr::null_mut};
use windows_sys::Win32::Graphics::Gdi::*;

struct Surface {
    dc: HDC,
    bitmap: HBITMAP,
    font: HFONT,
    old_bitmap: HGDIOBJ,
    old_font: HGDIOBJ,
}
impl Drop for Surface {
    fn drop(&mut self) {
        unsafe {
            if !self.old_font.is_null() {
                SelectObject(self.dc, self.old_font);
            }
            if !self.old_bitmap.is_null() {
                SelectObject(self.dc, self.old_bitmap);
            }
            if !self.font.is_null() {
                DeleteObject(self.font);
            }
            if !self.bitmap.is_null() {
                DeleteObject(self.bitmap);
            }
            if !self.dc.is_null() {
                DeleteDC(self.dc);
            }
        }
    }
}
fn color(tone: Tone) -> u32 {
    let (r, g, b) = match tone {
        Tone::Border => (105, 105, 115),
        Tone::Accent => (255, 209, 232),
        Tone::Secondary => (223, 192, 255),
        Tone::Text => (192, 192, 192),
        Tone::Primary => (245, 245, 245),
        Tone::Good => (80, 220, 100),
        Tone::Warning => (245, 210, 120),
        Tone::Bad => (245, 105, 105),
    };
    r | (g << 8) | (b << 16)
}
fn draw(dc: HDC, x: i32, y: i32, text: &str, tone: Tone) -> Result<()> {
    let text = text.encode_utf16().collect::<Vec<_>>();
    unsafe {
        SetTextColor(dc, color(tone));
        ensure!(
            TextOutW(dc, x, y, text.as_ptr(), text.len() as i32) != 0,
            "Draw menu text: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

impl Frame {
    pub fn save_png(self, output: &Path) -> Result<serde_json::Value> {
        let lines = self.complete();
        ensure!(
            !lines.is_empty() && lines.len() <= 256,
            "Invalid preview frame height"
        );
        let columns = lines
            .iter()
            .map(|line| {
                line.iter()
                    .map(|span| span.text.chars().count())
                    .sum::<usize>()
            })
            .max()
            .context("Empty preview")?;
        let mut surface = Surface {
            dc: null_mut(),
            bitmap: null_mut(),
            font: null_mut(),
            old_bitmap: null_mut(),
            old_font: null_mut(),
        };
        let (cell, height, pixels, width, image_height) = unsafe {
            surface.dc = CreateCompatibleDC(null_mut());
            ensure!(!surface.dc.is_null(), "Create preview device context");
            let font = "Consolas\0".encode_utf16().collect::<Vec<_>>();
            surface.font = CreateFontW(
                -20,
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                (FIXED_PITCH | FF_MODERN) as u32,
                font.as_ptr(),
            );
            ensure!(!surface.font.is_null(), "Create preview font");
            surface.old_font = SelectObject(surface.dc, surface.font);
            let mut metrics = TEXTMETRICW::default();
            ensure!(
                GetTextMetricsW(surface.dc, &mut metrics) != 0,
                "Measure preview font"
            );
            let cell = metrics.tmAveCharWidth.max(1);
            let height = (metrics.tmHeight + 4).max(1);
            let width = columns as i32 * cell + 48;
            let image_height = lines.len() as i32 * height + 88;
            ensure!(
                width > 0 && width <= 4096 && image_height > 0 && image_height <= 8192,
                "Preview exceeds image budget"
            );
            let info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    biHeight: -image_height,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut pixels = null_mut();
            surface.bitmap = CreateDIBSection(
                surface.dc,
                &info,
                DIB_RGB_COLORS,
                &mut pixels,
                null_mut(),
                0,
            );
            ensure!(
                !surface.bitmap.is_null() && !pixels.is_null(),
                "Create preview bitmap"
            );
            surface.old_bitmap = SelectObject(surface.dc, surface.bitmap);
            SetBkMode(surface.dc, TRANSPARENT as i32);
            (cell, height, pixels.cast::<u8>(), width, image_height)
        };
        let bytes = width as usize * image_height as usize * 4;
        // This top-down DIB belongs exclusively to this thread and stays selected
        // until after GDI flush and the RGB copy. No desktop/window is captured.
        unsafe {
            std::slice::from_raw_parts_mut(pixels, bytes)
                .chunks_exact_mut(4)
                .for_each(|pixel| pixel.copy_from_slice(&[12, 12, 12, 0]));
        }
        draw(
            surface.dc,
            24,
            16,
            "Предпросмотр · демонстрационные данные",
            Tone::Text,
        )?;
        let mut y = 58;
        for line in &lines {
            let mut x = 24;
            for span in line {
                draw(surface.dc, x, y, &span.text, span.tone)?;
                x += span.text.chars().count() as i32 * cell;
            }
            y += height;
        }
        unsafe {
            ensure!(GdiFlush() != 0, "Flush preview drawing");
        }
        let rgb = unsafe { std::slice::from_raw_parts(pixels, bytes) }
            .chunks_exact(4)
            .flat_map(|pixel| [pixel[2], pixel[1], pixel[0]])
            .collect::<Vec<_>>();
        let mut png = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png, width as u32, image_height as u32);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header()?;
            writer.write_image_data(&rgb)?;
            writer.finish()?;
        }
        let output = std::path::absolute(output)?;
        zapret_core::atomic_write(&output, &png)?;
        let text = lines
            .iter()
            .map(|line| {
                line.iter()
                    .map(|span| span.text.as_str())
                    .collect::<String>()
                    + "\n"
            })
            .collect::<String>();
        Ok(
            serde_json::json!({"output":output,"width":width,"height":image_height,"columns":columns,"rows":lines.len(),"sha256":zapret_core::sha256(&png),"text":text,"source":"NativeFrame","machine_state_read":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_png_decodes_and_keeps_the_actual_frame_text() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("меню с пробелами.png");
        let mut frame = Frame::new(
            super::super::Viewport {
                columns: 55,
                rows: 16,
            },
            "Проверка",
        );
        frame.item(2, "Остановить обход", Tone::Bad);
        let report = frame.save_png(&output).unwrap();
        let bytes = std::fs::read(&output).unwrap();
        let mut decoder = png::Decoder::new(std::io::Cursor::new(&bytes))
            .read_info()
            .unwrap();
        let mut pixels = vec![0; decoder.output_buffer_size()];
        let info = decoder.next_frame(&mut pixels).unwrap();
        assert_eq!(info.width as u64, report["width"].as_u64().unwrap());
        assert!(
            report["text"]
                .as_str()
                .unwrap()
                .contains("Остановить обход")
        );
        assert_eq!(report["machine_state_read"], false);
        assert!(pixels.chunks_exact(3).any(|p| p != [12, 12, 12]));
    }
}
