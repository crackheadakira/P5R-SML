use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use once_cell::sync::Lazy;

use crate::utils::logging::debug_print;

// Thank you to Sewer56's work on the SPD File Emulation for figuring out file format

const HEADER_SIZE: usize = 0x20;
const TEXTURE_ENTRY_SIZE: usize = 0x30;
const SPRITE_ENTRY_SIZE: usize = 0xa0;

struct SpdModEntry {
    /// `tex_<id>.dds` or `spr_<id>[_<id>].dds` files.
    dds_files: Vec<PathBuf>,
    /// `spr_<id>.spdspr` override files (raw SpdSpriteEntry blobs).
    spdspr_files: Vec<PathBuf>,
}

static SPD_MODS: Lazy<Mutex<HashMap<String, SpdModEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Call this at startup for every mod folder (same loop that calls
/// `binders.load_mod_folder`).  Walks `<mod>/FEmulator/SPD/` recursively,
/// finds `*.spd` directories, registers their contents.
pub fn register_spd_mod(mod_folder: &Path) {
    let redirector = mod_folder.join("FEmulator/SPD");
    if !redirector.exists() {
        return;
    }
    walk_for_spd_dirs(&redirector);
}

fn walk_for_spd_dirs(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if name.ends_with(".spd") {
            collect_spd_mod_files(&path, &name);
        } else {
            walk_for_spd_dirs(&path);
        }
    }
}

fn collect_spd_mod_files(spd_dir: &Path, spd_key: &str) {
    let Ok(entries) = fs::read_dir(spd_dir) else {
        return;
    };

    let mut dds_files = Vec::new();
    let mut spdspr_files = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "dds" => dds_files.push(path),
            "spdspr" => spdspr_files.push(path),
            _ => {}
        }
    }

    if dds_files.is_empty() && spdspr_files.is_empty() {
        return;
    }

    debug_print(&format!(
        "[SPD] Registered {} dds + {} spdspr for '{spd_key}'",
        dds_files.len(),
        spdspr_files.len()
    ));

    let mut mods = SPD_MODS.lock().unwrap();
    let entry = mods
        .entry(spd_key.to_string())
        .or_insert_with(|| SpdModEntry {
            dds_files: Vec::new(),
            spdspr_files: Vec::new(),
        });
    entry.dds_files.extend(dds_files);
    entry.spdspr_files.extend(spdspr_files);
}

/// Patch the raw SPD buffer in-place before the game parses it.
/// Returns the number of sprites patched, or `None` if no mod is registered
/// for this SPD.
pub fn patch_spd_bytes(normalised_path: &str, buf: &mut [u8]) -> Option<usize> {
    let key = Path::new(normalised_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(normalised_path)
        .to_ascii_lowercase();

    let mods = SPD_MODS.lock().unwrap();
    let mod_entry = mods.get(&key)?;

    if buf.len() < HEADER_SIZE {
        return None;
    }

    let texture_count = i16::from_le_bytes(buf[0x14..0x16].try_into().ok()?) as usize;
    let sprite_count = i16::from_le_bytes(buf[0x16..0x18].try_into().ok()?) as usize;
    let texture_offset = i32::from_le_bytes(buf[0x18..0x1c].try_into().ok()?) as usize;
    let sprite_offset = i32::from_le_bytes(buf[0x1c..0x20].try_into().ok()?) as usize;

    let textures_end = texture_offset + texture_count * TEXTURE_ENTRY_SIZE;
    let sprites_end = sprite_offset + sprite_count * SPRITE_ENTRY_SIZE;
    if buf.len() < textures_end || buf.len() < sprites_end {
        debug_print("[SPD] Buffer too small for declared entry counts, skipping");
        return None;
    }

    let mut sprite_offsets: HashMap<i32, usize> = HashMap::new();
    for i in 0..sprite_count {
        let off = sprite_offset + i * SPRITE_ENTRY_SIZE;
        let id = i32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
        sprite_offsets.insert(id, off);
    }

    debug_print(&format!(
        "[SPD] '{key}' has {} sprites: {:?}",
        sprite_offsets.len(),
        sprite_offsets.keys().collect::<Vec<_>>()
    ));

    for dds_path in &mod_entry.dds_files {
        debug_print(&format!("[SPD] Processing DDS: {:?}", dds_path.file_name()));
    }
    for spdspr_path in &mod_entry.spdspr_files {
        debug_print(&format!(
            "[SPD] Processing spdspr: {:?}",
            spdspr_path.file_name()
        ));
    }

    let mut texture_offsets: HashMap<i32, usize> = HashMap::new();
    for i in 0..texture_count {
        let off = texture_offset + i * TEXTURE_ENTRY_SIZE;
        let id = i32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
        texture_offsets.insert(id, off);
    }

    let mut n_patched = 0;

    for spdspr_path in &mod_entry.spdspr_files {
        let stem = spdspr_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let Some(rest) = stem.strip_prefix("spr_") else {
            continue;
        };
        let Ok(sprite_id) = rest.parse::<i32>() else {
            continue;
        };

        let Ok(blob) = fs::read(spdspr_path) else {
            debug_print(&format!("[SPD] Failed to read {:?}", spdspr_path));
            continue;
        };
        if blob.len() < SPRITE_ENTRY_SIZE {
            debug_print(&format!("[SPD] .spdspr too small: {:?}", spdspr_path));
            continue;
        }

        if let Some(&off) = sprite_offsets.get(&sprite_id) {
            buf[off..off + SPRITE_ENTRY_SIZE].copy_from_slice(&blob[..SPRITE_ENTRY_SIZE]);
            n_patched += 1;
            debug_print(&format!("[SPD] Patched sprite {sprite_id} from spdspr"));
        } else {
            debug_print(&format!(
                "[SPD] Sprite id {sprite_id} not found in SPD, skipping"
            ));
        }
    }

    for dds_path in &mod_entry.dds_files {
        let stem = dds_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

        let Ok(dds_bytes) = fs::read(dds_path) else {
            debug_print(&format!("[SPD] Failed to read {:?}", dds_path));
            continue;
        };

        if dds_bytes.len() < 0x14 {
            debug_print(&format!("[SPD] DDS too small: {:?}", dds_path));
            continue;
        }

        let dds_height = i32::from_le_bytes(dds_bytes[0x0c..0x10].try_into().unwrap());
        let dds_width = i32::from_le_bytes(dds_bytes[0x10..0x14].try_into().unwrap());

        let sprite_ids_to_patch: Vec<i32> = if let Some(rest) = stem.strip_prefix("spr_") {
            parse_sprite_ids(rest).into_iter().collect()
        } else if let Some(rest) = stem.strip_prefix("tex_") {
            let parts: Vec<&str> = rest.splitn(2, '~').collect();
            let Ok(tex_id) = parts[0].parse::<i32>() else {
                continue;
            };
            let exclude: std::collections::HashSet<i32> = if parts.len() > 1 {
                parse_sprite_ids(parts[1])
            } else {
                std::collections::HashSet::new()
            };
            sprite_offsets
                .keys()
                .copied()
                .filter(|&id| {
                    if exclude.contains(&id) {
                        return false;
                    }
                    if let Some(&off) = sprite_offsets.get(&id) {
                        let tid = i32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
                        tid == tex_id
                    } else {
                        false
                    }
                })
                .collect()
        } else {
            continue;
        };

        if sprite_ids_to_patch.is_empty() {
            continue;
        }

        let first_sprite_off = match sprite_ids_to_patch
            .first()
            .and_then(|id| sprite_offsets.get(id))
        {
            Some(&off) => off,
            None => continue,
        };
        let target_tex_id = i32::from_le_bytes(
            buf[first_sprite_off + 4..first_sprite_off + 8]
                .try_into()
                .unwrap(),
        );

        let Some(&tex_entry_off) = texture_offsets.get(&target_tex_id) else {
            debug_print(&format!(
                "[SPD] Could not find texture entry for id {target_tex_id}"
            ));
            continue;
        };

        let existing_data_offset = i32::from_le_bytes(
            buf[tex_entry_off + 8..tex_entry_off + 12]
                .try_into()
                .unwrap(),
        ) as usize;
        let existing_data_size = i32::from_le_bytes(
            buf[tex_entry_off + 12..tex_entry_off + 16]
                .try_into()
                .unwrap(),
        ) as usize;

        if dds_bytes.len() <= existing_data_size
            && existing_data_offset + dds_bytes.len() <= buf.len()
        {
            buf[existing_data_offset..existing_data_offset + dds_bytes.len()]
                .copy_from_slice(&dds_bytes);

            buf[tex_entry_off + 8..tex_entry_off + 12]
                .copy_from_slice(&(existing_data_offset as i32).to_le_bytes());
            buf[tex_entry_off + 12..tex_entry_off + 16]
                .copy_from_slice(&(dds_bytes.len() as i32).to_le_bytes());
            buf[tex_entry_off + 16..tex_entry_off + 20].copy_from_slice(&dds_width.to_le_bytes());
            buf[tex_entry_off + 20..tex_entry_off + 24].copy_from_slice(&dds_height.to_le_bytes());

            for sprite_id in &sprite_ids_to_patch {
                if let Some(&off) = sprite_offsets.get(sprite_id) {
                    buf[off + 4..off + 8].copy_from_slice(&target_tex_id.to_le_bytes());
                    n_patched += 1;
                }
            }

            debug_print(&format!(
                "[SPD] Replaced texture {target_tex_id} with {:?} ({} bytes)",
                dds_path.file_name().unwrap_or_default(),
                dds_bytes.len()
            ));
        } else {
            debug_print(&format!(
                "[SPD] Replacement DDS ({} bytes) is larger than existing texture slot ({existing_data_size} bytes), cannot patch in-place. Dump the original SPD, pack your DDS smaller, or use .spdspr overrides only.",
                dds_bytes.len()
            ));
        }
    }

    Some(n_patched)
}

fn parse_sprite_ids(s: &str) -> std::collections::HashSet<i32> {
    let mut ids = std::collections::HashSet::new();
    for part in s.split('_') {
        if part.contains('-') {
            let mut it = part.splitn(2, '-');
            if let (Some(lo), Some(hi)) = (it.next(), it.next()) {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<i32>(), hi.parse::<i32>()) {
                    for i in lo..=hi {
                        ids.insert(i);
                    }
                }
            }
        } else if let Ok(id) = part.parse::<i32>() {
            ids.insert(id);
        }
    }
    ids
}
