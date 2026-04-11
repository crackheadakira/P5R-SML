use std::{collections::HashMap, fs, path::PathBuf};

use crate::utils::logging::debug_print;

// Thanks to Amicitia by tge-was-taken & SPD File Emulation by Sewer56
// I was able to see how they had implemeneted the SPD layout.

// SPD layout (all little-endian)
//
// Header (0x20 bytes):
//   0x00  magic            [u8; 4]  "SPR0"
//   0x04  unk04            i32
//   0x08  file_size        i64
//   0x10  unk10            i32
//   0x14  texture_count    i16
//   0x16  sprite_count     i16
//   0x18  texture_offset   i32      offset from file start to texture entry table
//   0x1c  sprite_offset    i32      offset from file start to sprite entry table
//
// Texture entry (0x30 bytes):
//   0x00  texture_id       i32
//   0x04  unk04            i32
//   0x08  data_offset      i32      offset from file start to texture blob
//   0x0c  data_size        i32
//   0x10  width            i32
//   0x14  height           i32
//   0x18  unk18            i32
//   0x1c  unk1c            i32
//   0x20  name             [u8; 16]
//
// Sprite entry (0xa0 bytes):
//   0x00  sprite_id        i32
//   0x04  texture_id       i32
//   0x08..0x6f  various fields
//   0x70  name             [u8; 48]

const HEADER_SIZE: usize = 0x20;
const TEXTURE_ENTRY_SIZE: usize = 0x30;
const SPRITE_ENTRY_SIZE: usize = 0xa0;

#[derive(Clone)]
struct TextureEntry {
    raw: [u8; TEXTURE_ENTRY_SIZE],
}

impl TextureEntry {
    fn id(&self) -> i32 {
        i32::from_le_bytes(self.raw[0..4].try_into().unwrap())
    }
    fn data_offset(&self) -> i32 {
        i32::from_le_bytes(self.raw[8..12].try_into().unwrap())
    }
    fn data_size(&self) -> i32 {
        i32::from_le_bytes(self.raw[12..16].try_into().unwrap())
    }
    fn set_data_offset(&mut self, v: i32) {
        self.raw[8..12].copy_from_slice(&v.to_le_bytes());
    }
    fn set_data_size(&mut self, v: i32) {
        self.raw[12..16].copy_from_slice(&v.to_le_bytes());
    }
    fn set_width(&mut self, v: i32) {
        self.raw[16..20].copy_from_slice(&v.to_le_bytes());
    }
    fn set_height(&mut self, v: i32) {
        self.raw[20..24].copy_from_slice(&v.to_le_bytes());
    }
    fn set_id(&mut self, v: i32) {
        self.raw[0..4].copy_from_slice(&v.to_le_bytes());
    }
    fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        self.raw[0x20..0x30].fill(0);
        let n = bytes.len().min(15);
        self.raw[0x20..0x20 + n].copy_from_slice(&bytes[..n]);
    }
}

#[derive(Clone)]
struct SpriteEntry {
    raw: [u8; SPRITE_ENTRY_SIZE],
}

impl SpriteEntry {
    fn id(&self) -> i32 {
        i32::from_le_bytes(self.raw[0..4].try_into().unwrap())
    }
    fn texture_id(&self) -> i32 {
        i32::from_le_bytes(self.raw[4..8].try_into().unwrap())
    }
    fn set_texture_id(&mut self, v: i32) {
        self.raw[4..8].copy_from_slice(&v.to_le_bytes());
    }
}

fn parse_header(buf: &[u8]) -> Option<(i16, i16, i32, i32)> {
    if buf.len() < HEADER_SIZE {
        return None;
    }
    if &buf[0..4] != b"SPR0" {
        return None;
    }
    let tex_count = i16::from_le_bytes(buf[0x14..0x16].try_into().ok()?);
    let spr_count = i16::from_le_bytes(buf[0x16..0x18].try_into().ok()?);
    let tex_offset = i32::from_le_bytes(buf[0x18..0x1c].try_into().ok()?);
    let spr_offset = i32::from_le_bytes(buf[0x1c..0x20].try_into().ok()?);
    Some((tex_count, spr_count, tex_offset, spr_offset))
}

fn parse_texture_entries(buf: &[u8], count: i16, offset: i32) -> Vec<TextureEntry> {
    let mut entries = Vec::new();
    for i in 0..count as usize {
        let start = offset as usize + i * TEXTURE_ENTRY_SIZE;
        let end = start + TEXTURE_ENTRY_SIZE;
        if end > buf.len() {
            break;
        }
        let mut raw = [0u8; TEXTURE_ENTRY_SIZE];
        raw.copy_from_slice(&buf[start..end]);
        entries.push(TextureEntry { raw });
    }
    entries
}

fn parse_sprite_entries(buf: &[u8], count: i16, offset: i32) -> Vec<SpriteEntry> {
    let mut entries = Vec::new();
    for i in 0..count as usize {
        let start = offset as usize + i * SPRITE_ENTRY_SIZE;
        let end = start + SPRITE_ENTRY_SIZE;
        if end > buf.len() {
            break;
        }
        let mut raw = [0u8; SPRITE_ENTRY_SIZE];
        raw.copy_from_slice(&buf[start..end]);
        entries.push(SpriteEntry { raw });
    }
    entries
}

fn parse_sprite_ids(s: &str) -> Vec<i32> {
    let mut ids = Vec::new();
    for part in s.split('_') {
        if part.contains('-') {
            let mut it = part.splitn(2, '-');
            if let (Some(lo), Some(hi)) = (it.next(), it.next())
                && let (Ok(lo), Ok(hi)) = (lo.parse::<i32>(), hi.parse::<i32>())
            {
                for i in lo..=hi {
                    ids.push(i);
                }
            }
        } else if let Ok(id) = part.parse::<i32>() {
            ids.push(id);
        }
    }
    ids
}

pub struct SpdModFiles {
    pub dds_files: Vec<PathBuf>,
    pub spdspr_files: Vec<PathBuf>,
}

/// Build a fully patched SPD from the original bytes and a set of mod files.
/// Implements Smart Overwrite: Overwrites textures in-place when safe to keep file size small,
/// and appends new textures when patching shared atlases to prevent corruption.
pub fn build_patched_spd(original: &[u8], mod_files: &SpdModFiles) -> Option<Vec<u8>> {
    let (tex_count, spr_count, tex_offset, spr_offset) = parse_header(original)?;

    let mut textures = parse_texture_entries(original, tex_count, tex_offset);
    let mut sprites = parse_sprite_entries(original, spr_count, spr_offset);

    let mut texture_blobs: HashMap<i32, Vec<u8>> = HashMap::new();
    for tex in &textures {
        let off = tex.data_offset() as usize;
        let size = tex.data_size() as usize;
        if off + size <= original.len() {
            texture_blobs.insert(tex.id(), original[off..off + size].to_vec());
        }
    }

    let next_tex_id = textures.iter().map(|t| t.id()).max().unwrap_or(0) + 1;

    let sprite_idx: HashMap<i32, usize> = sprites
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id(), i))
        .collect();

    let mut tex_to_sprites: HashMap<i32, Vec<i32>> = HashMap::new();
    for s in &sprites {
        tex_to_sprites
            .entry(s.texture_id())
            .or_default()
            .push(s.id());
    }

    let mut new_tex_id = next_tex_id;

    for path in &mod_files.spdspr_files {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let Some(rest) = stem.strip_prefix("spr_") else {
            continue;
        };
        let Ok(sprite_id) = rest.parse::<i32>() else {
            continue;
        };

        let Ok(blob) = fs::read(path) else {
            debug_print!("[SPD] Failed to read {path:?}");
            continue;
        };
        if blob.len() < SPRITE_ENTRY_SIZE {
            continue;
        }

        if let Some(&idx) = sprite_idx.get(&sprite_id) {
            sprites[idx].raw.copy_from_slice(&blob[..SPRITE_ENTRY_SIZE]);
        }
    }

    for path in &mod_files.dds_files {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

        let Ok(dds) = fs::read(path) else {
            continue;
        };
        if dds.len() < 0x14 {
            continue;
        }

        let dds_height = i32::from_le_bytes(dds[0x0c..0x10].try_into().unwrap());
        let dds_width = i32::from_le_bytes(dds[0x10..0x14].try_into().unwrap());

        let explicit_tex_id = if stem.starts_with("tex_") && !stem.contains('~') {
            stem.strip_prefix("tex_").unwrap().parse::<i32>().ok()
        } else {
            None
        };

        if let Some(tex_id) = explicit_tex_id {
            if let Some(tex) = textures.iter_mut().find(|t| t.id() == tex_id) {
                tex.set_data_size(dds.len() as i32);
                tex.set_width(dds_width);
                tex.set_height(dds_height);
                texture_blobs.insert(tex_id, dds.clone());
                debug_print!("[SPD] Explicitly overwrote texture ID {tex_id}");
            }
            continue;
        }

        let target_sprite_ids: Vec<i32> = if let Some(rest) = stem.strip_prefix("spr_") {
            parse_sprite_ids(rest)
        } else if let Some(rest) = stem.strip_prefix("tex_") {
            let parts: Vec<&str> = rest.splitn(2, '~').collect();
            let Ok(tex_id) = parts[0].parse::<i32>() else {
                continue;
            };
            let exclude: std::collections::HashSet<i32> = if parts.len() > 1 {
                parse_sprite_ids(parts[1]).into_iter().collect()
            } else {
                std::collections::HashSet::new()
            };
            tex_to_sprites
                .get(&tex_id)
                .map(|ids| {
                    ids.iter()
                        .filter(|id| !exclude.contains(id))
                        .copied()
                        .collect()
                })
                .unwrap_or_default()
        } else {
            continue;
        };

        if target_sprite_ids.is_empty() {
            continue;
        }

        let target_set: std::collections::HashSet<i32> =
            target_sprite_ids.iter().copied().collect();
        let mut affected_tex_ids = std::collections::HashSet::new();
        for sid in &target_sprite_ids {
            if let Some(&idx) = sprite_idx.get(sid) {
                affected_tex_ids.insert(sprites[idx].texture_id());
            }
        }

        let mut safe_to_overwrite = !affected_tex_ids.is_empty();
        for &tex_id in &affected_tex_ids {
            if let Some(sprites_on_this_tex) = tex_to_sprites.get(&tex_id) {
                if !sprites_on_this_tex.iter().all(|s| target_set.contains(s)) {
                    safe_to_overwrite = false;
                    break;
                }
            }
        }

        if safe_to_overwrite {
            for &tex_id in &affected_tex_ids {
                if let Some(tex) = textures.iter_mut().find(|t| t.id() == tex_id) {
                    tex.set_data_size(dds.len() as i32);
                    tex.set_width(dds_width);
                    tex.set_height(dds_height);
                    texture_blobs.insert(tex_id, dds.clone());
                    debug_print!(
                        "[SPD] Safely overwrote texture ID {tex_id} (no shared atlas conflict)"
                    );
                }
            }
        } else {
            let mut new_entry = TextureEntry {
                raw: [0u8; TEXTURE_ENTRY_SIZE],
            };
            new_entry.set_id(new_tex_id);
            new_entry.set_data_offset(0);
            new_entry.set_data_size(dds.len() as i32);
            new_entry.set_width(dds_width);
            new_entry.set_height(dds_height);
            new_entry.set_name(&format!("texture_{new_tex_id}"));

            texture_blobs.insert(new_tex_id, dds);
            textures.push(new_entry);

            for sprite_id in &target_sprite_ids {
                if let Some(&idx) = sprite_idx.get(sprite_id) {
                    sprites[idx].set_texture_id(new_tex_id);
                    debug_print!(
                        "[SPD] Shared Atlas detected. Appended new texture ID {new_tex_id} for Sprite ID {sprite_id}"
                    );
                }
            }
            new_tex_id += 1;
        }
    }

    let tex_entries_start = HEADER_SIZE;
    let spr_entries_start = tex_entries_start + textures.len() * TEXTURE_ENTRY_SIZE;
    let blobs_start = spr_entries_start + sprites.len() * SPRITE_ENTRY_SIZE;

    let mut blob_offset = blobs_start;
    let mut ordered_tex_ids: Vec<i32> = textures.iter().map(|t| t.id()).collect();
    ordered_tex_ids.sort();

    let total_blob_size: usize = ordered_tex_ids
        .iter()
        .map(|id| texture_blobs.get(id).map(|b| b.len()).unwrap_or(0))
        .sum();

    let total_size = blobs_start + total_blob_size;
    let mut out = vec![0u8; total_size];

    out[0..HEADER_SIZE].copy_from_slice(&original[0..HEADER_SIZE]);
    out[0x14..0x16].copy_from_slice(&(textures.len() as i16).to_le_bytes());
    out[0x16..0x18].copy_from_slice(&(sprites.len() as i16).to_le_bytes());
    out[0x18..0x1c].copy_from_slice(&(tex_entries_start as i32).to_le_bytes());
    out[0x1c..0x20].copy_from_slice(&(spr_entries_start as i32).to_le_bytes());
    out[0x08..0x10].copy_from_slice(&(total_size as i64).to_le_bytes());

    let mut tex_write_pos = tex_entries_start;
    for id in &ordered_tex_ids {
        let tex = textures.iter_mut().find(|t| t.id() == *id).unwrap();
        let blob_len = texture_blobs.get(id).map(|b| b.len()).unwrap_or(0);
        tex.set_data_offset(blob_offset as i32);
        tex.set_data_size(blob_len as i32);
        out[tex_write_pos..tex_write_pos + TEXTURE_ENTRY_SIZE].copy_from_slice(&tex.raw);
        blob_offset += blob_len;
        tex_write_pos += TEXTURE_ENTRY_SIZE;
    }

    let mut spr_write_pos = spr_entries_start;
    for spr in &sprites {
        out[spr_write_pos..spr_write_pos + SPRITE_ENTRY_SIZE].copy_from_slice(&spr.raw);
        spr_write_pos += SPRITE_ENTRY_SIZE;
    }

    let mut blob_write_pos = blobs_start;
    for id in &ordered_tex_ids {
        if let Some(blob) = texture_blobs.get(id) {
            out[blob_write_pos..blob_write_pos + blob.len()].copy_from_slice(blob);
            blob_write_pos += blob.len();
        }
    }

    debug_print!(
        "[SPD] Built patched SPD: {total_size} bytes (was {} bytes, {} textures, {} sprites)",
        original.len(),
        textures.len(),
        sprites.len()
    );

    Some(out)
}
