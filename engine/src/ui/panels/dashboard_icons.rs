//! Optional, per-user artwork. Distributed builds do not include third-party assets.

use std::{fs::File, io::{Cursor, Read, BufReader}, path::Path};

use eframe::egui::{self, ColorImage, TextureHandle, TextureOptions, Ui, Vec2};

const MAX_FILE: u64 = 512 * 1024;
const MAX_DIMENSION: u32 = 512;

pub(crate) fn paint(ui: &mut Ui, dark: bool, icon: &'static str, width: f32) -> bool {
    let id = egui::Id::new(("local-dashboard-icon", icon, dark));
    let cached = ui.ctx().data(|data| data.get_temp::<Option<TextureHandle>>(id));
    let texture = cached.unwrap_or_else(|| {
        let filename = format!("{icon}-{}.png", if dark { "dark" } else { "light" });
        let texture = crate::platform_paths::data_dir().ok()
            .and_then(|dir| read_image(&dir.join("dashboard-icons").join(filename)))
            .map(|image| ui.ctx().load_texture(format!("local-{icon}-{dark}"), image, TextureOptions::LINEAR));
        ui.ctx().data_mut(|data| data.insert_temp(id, texture.clone()));
        texture
    });
    if let Some(texture) = texture {
        let size = texture.size_vec2();
        ui.image((texture.id(), Vec2::new(width, width * size.y / size.x)));
        true
    } else {
        false
    }
}

fn read_image(path: &Path) -> Option<ColorImage> {
    // An optional icon can't turn into an unbounded decode or delay the UI via a special file.
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return None;
    }
    let mut data = Vec::new();
    File::open(path).ok()?.take(MAX_FILE + 1).read_to_end(&mut data).ok()?;
    if data.len() as u64 > MAX_FILE {
        return None;
    }
    decode(&data)
}

fn decode(bytes: &[u8]) -> Option<ColorImage> {
    let mut decoder = png::Decoder::new(BufReader::new(Cursor::new(bytes)));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let (width, height) = reader.info().size();
    if !(1..=MAX_DIMENSION).contains(&width) || !(1..=MAX_DIMENSION).contains(&height) {
        return None;
    }
    let mut buffer = vec![0; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut buffer).ok()?;
    let size = [frame.width as usize, frame.height as usize];
    let pixels = &buffer[..frame.buffer_size()];
    match frame.color_type {
        png::ColorType::Rgba => Some(ColorImage::from_rgba_unmultiplied(size, pixels)),
        png::ColorType::Rgb => Some(ColorImage::from_rgb(size, pixels)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(width: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, 1);
        encoder.set_color(png::ColorType::Rgba);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&vec![255; width as usize * 4]).unwrap();
        writer.finish().unwrap();
        bytes
    }

    #[test]
    fn extensions_of_icon_format_are_bounded() {
        assert_eq!(decode(&fixture(1)).unwrap().size, [1, 1]);
        assert!(decode(&fixture(513)).is_none());
        assert!(decode(b"not a PNG").is_none());
        assert!(read_image(Path::new("/nonexistent-gulpsuite-fixture.png")).is_none());
    }
}
