use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

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
        self.raw[0x20..0x30].fill(0);
        let b = name.as_bytes();
        let n = b.len().min(15);
        self.raw[0x20..0x20 + n].copy_from_slice(&b[..n]);
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

enum Blob<'a> {
    /// Slice into the original buffer — no allocation.
    Borrowed(&'a [u8]),

    /// Owned bytes for new/replaced textures.
    Owned(Vec<u8>),
}

impl<'a> Blob<'a> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Blob::Borrowed(s) => s,
            Blob::Owned(v) => v,
        }
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }
}

fn parse_header(buf: &[u8]) -> Option<(i16, i16, i32, i32)> {
    if buf.len() < HEADER_SIZE || &buf[0..4] != b"SPR0" {
        return None;
    }

    let tex_count = i16::from_le_bytes(buf[0x14..0x16].try_into().ok()?);
    let spr_count = i16::from_le_bytes(buf[0x16..0x18].try_into().ok()?);
    let tex_offset = i32::from_le_bytes(buf[0x18..0x1c].try_into().ok()?);
    let spr_offset = i32::from_le_bytes(buf[0x1c..0x20].try_into().ok()?);
    Some((tex_count, spr_count, tex_offset, spr_offset))
}

fn parse_texture_entries(buf: &[u8], count: i16, offset: i32) -> Vec<TextureEntry> {
    (0..count as usize)
        .filter_map(|i| {
            let start = offset as usize + i * TEXTURE_ENTRY_SIZE;
            let end = start + TEXTURE_ENTRY_SIZE;

            if end > buf.len() {
                return None;
            }

            let mut raw = [0u8; TEXTURE_ENTRY_SIZE];
            raw.copy_from_slice(&buf[start..end]);
            Some(TextureEntry { raw })
        })
        .collect()
}

fn parse_sprite_entries(buf: &[u8], count: i16, offset: i32) -> Vec<SpriteEntry> {
    (0..count as usize)
        .filter_map(|i| {
            let start = offset as usize + i * SPRITE_ENTRY_SIZE;
            let end = start + SPRITE_ENTRY_SIZE;

            if end > buf.len() {
                return None;
            }

            let mut raw = [0u8; SPRITE_ENTRY_SIZE];
            raw.copy_from_slice(&buf[start..end]);
            Some(SpriteEntry { raw })
        })
        .collect()
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
///
/// Implements Smart Overwrite: Overwrites textures in-place when safe to keep file size small,
/// and appends new textures when patching shared atlases to prevent corruption.
///
/// Untouched texture blobs are borrowed directly from `original` (no copy.)
pub fn build_patched_spd<'a>(original: &'a [u8], mod_files: &SpdModFiles) -> Option<Vec<u8>> {
    let (tex_count, spr_count, tex_offset, spr_offset) = parse_header(original)?;

    let mut textures = parse_texture_entries(original, tex_count, tex_offset);
    let mut sprites = parse_sprite_entries(original, spr_count, spr_offset);

    let mut tex_idx: HashMap<i32, usize> = textures
        .iter()
        .enumerate()
        .map(|(i, t)| (t.id(), i))
        .collect();

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

    let mut blobs: HashMap<i32, Blob<'a>> = textures
        .iter()
        .filter_map(|t| {
            let off = i32::from_le_bytes(t.raw[8..12].try_into().unwrap()) as usize;
            let size = i32::from_le_bytes(t.raw[12..16].try_into().unwrap()) as usize;
            if off + size <= original.len() {
                Some((t.id(), Blob::Borrowed(&original[off..off + size])))
            } else {
                None
            }
        })
        .collect();

    let mut next_tex_id = textures.iter().map(|t| t.id()).max().unwrap_or(0) + 1;

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

        let Ok(dds) = fs::read(path) else { continue };
        if dds.len() < 0x14 {
            continue;
        }

        let dds_h = i32::from_le_bytes(dds[0x0c..0x10].try_into().unwrap());
        let dds_w = i32::from_le_bytes(dds[0x10..0x14].try_into().unwrap());

        if let Some(rest) = stem.strip_prefix("tex_")
            && !rest.contains('~')
            && let Ok(tex_id) = rest.parse::<i32>()
        {
            if let Some(&ti) = tex_idx.get(&tex_id) {
                textures[ti].set_data_size(dds.len() as i32);
                textures[ti].set_width(dds_w);
                textures[ti].set_height(dds_h);
                blobs.insert(tex_id, Blob::Owned(dds));
                debug_print!("[SPD] Explicitly overwrote texture ID {tex_id}");
            }
            continue;
        }

        let target_ids: Vec<i32> = if let Some(rest) = stem.strip_prefix("spr_") {
            parse_sprite_ids(rest)
        } else if let Some(rest) = stem.strip_prefix("tex_") {
            let parts: Vec<&str> = rest.splitn(2, '~').collect();
            let Ok(tex_id) = parts[0].parse::<i32>() else {
                continue;
            };
            let exclude: HashSet<i32> = if parts.len() > 1 {
                parse_sprite_ids(parts[1]).into_iter().collect()
            } else {
                HashSet::new()
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

        if target_ids.is_empty() {
            continue;
        }

        let target_set: HashSet<i32> = target_ids.iter().copied().collect();

        let affected_tex_ids: HashSet<i32> = target_ids
            .iter()
            .filter_map(|sid| sprite_idx.get(sid).map(|&i| sprites[i].texture_id()))
            .collect();

        let safe = !affected_tex_ids.is_empty()
            && affected_tex_ids.iter().all(|&tid| {
                tex_to_sprites
                    .get(&tid)
                    .map(|all| all.iter().all(|s| target_set.contains(s)))
                    .unwrap_or(false)
            });

        if safe {
            for &tex_id in &affected_tex_ids {
                if let Some(&ti) = tex_idx.get(&tex_id) {
                    textures[ti].set_data_size(dds.len() as i32);
                    textures[ti].set_width(dds_w);
                    textures[ti].set_height(dds_h);
                }
                blobs.insert(tex_id, Blob::Owned(dds.clone()));
                debug_print!("[SPD] Overwrote texture ID {tex_id} (no shared atlas conflict)");
            }
            // If only one affected texture, we cloned once unnecessarily, fix by
            // re-inserting the move. Small SPD texture counts make this negligible.
        } else {
            let new_raw = [0u8; TEXTURE_ENTRY_SIZE];
            let new_entry_tmp = TextureEntry { raw: new_raw };
            let mut new_entry = new_entry_tmp;
            new_entry.set_id(next_tex_id);
            new_entry.set_data_offset(0); // filled during assembly
            new_entry.set_data_size(dds.len() as i32);
            new_entry.set_width(dds_w);
            new_entry.set_height(dds_h);
            new_entry.set_name(&format!("texture_{next_tex_id}"));

            tex_idx.insert(next_tex_id, textures.len());
            textures.push(new_entry);
            blobs.insert(next_tex_id, Blob::Owned(dds));

            for sid in &target_ids {
                if let Some(&si) = sprite_idx.get(sid) {
                    sprites[si].set_texture_id(next_tex_id);
                    debug_print!(
                        "[SPD] Shared atlas: appended texture {next_tex_id} for sprite {sid}"
                    );
                }
            }
            next_tex_id += 1;
        }
    }

    let tex_table_start = HEADER_SIZE;
    let spr_table_start = tex_table_start + textures.len() * TEXTURE_ENTRY_SIZE;
    let blobs_start = spr_table_start + sprites.len() * SPRITE_ENTRY_SIZE;

    let total_blob_size: usize = textures
        .iter()
        .map(|t| blobs.get(&t.id()).map(|b| b.len()).unwrap_or(0))
        .sum();

    let total_size = blobs_start + total_blob_size;
    let mut out = Vec::with_capacity(total_size);

    out.extend_from_slice(&original[..HEADER_SIZE]);
    out[0x08..0x10].copy_from_slice(&(total_size as i64).to_le_bytes());
    out[0x14..0x16].copy_from_slice(&(textures.len() as i16).to_le_bytes());
    out[0x16..0x18].copy_from_slice(&(sprites.len() as i16).to_le_bytes());
    out[0x18..0x1c].copy_from_slice(&(tex_table_start as i32).to_le_bytes());
    out[0x1c..0x20].copy_from_slice(&(spr_table_start as i32).to_le_bytes());

    let mut cursor = blobs_start;
    for tex in &mut textures {
        let blob_len = blobs.get(&tex.id()).map(|b| b.len()).unwrap_or(0);
        tex.set_data_offset(cursor as i32);
        out.extend_from_slice(&tex.raw);
        cursor += blob_len;
    }

    for spr in &sprites {
        out.extend_from_slice(&spr.raw);
    }

    for tex in &textures {
        if let Some(blob) = blobs.get(&tex.id()) {
            out.extend_from_slice(blob.as_slice());
        }
    }

    debug_print!(
        "[SPD] Built: {total_size} bytes (was {}, {} tex, {} spr)",
        original.len(),
        textures.len(),
        sprites.len()
    );

    Some(out)
}
