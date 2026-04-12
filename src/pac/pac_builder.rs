use crate::utils::logging::debug_print;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PacVersion {
    Version1,
    Version2,
    Version2BE,
    Version3,
    Version3BE,
    Unknown,
}

#[derive(Clone)]
struct PacEntry {
    name: String,
    original_offset: usize,
    original_size: usize,
}

#[derive(Clone, Debug)]
pub struct PacModFiles {
    pub replacements: HashMap<String, PathBuf>,
}

fn align_64(val: usize) -> usize {
    (val + 63) & !63
}

fn is_valid_v1(data: &[u8]) -> bool {
    if data.len() <= 256 {
        return false;
    }
    if data[0] == 0x00 {
        return false;
    }

    let mut name_terminated = false;

    for item in data.iter().take(252) {
        if *item == 0x00 {
            name_terminated = true;
        }

        if *item != 0x00 && name_terminated {
            return false;
        }
    }

    let first_len = u32::from_le_bytes(data[252..256].try_into().unwrap()) as usize;
    if first_len >= data.len() {
        return false;
    }

    true
}

fn is_valid_v2_v3(data: &[u8], entry_size: usize) -> Option<bool> {
    if data.len() <= 4 + entry_size {
        return None;
    }

    let mut num_files = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut is_be = false;

    if num_files > 1024 || (num_files * entry_size) > data.len() {
        num_files = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
        if num_files > 1024 || num_files == 0 || (num_files * entry_size) > data.len() {
            return None;
        }
        is_be = true;
    }

    let mut name_terminated = false;
    for i in 0..(entry_size - 4) {
        let b = data[4 + i];
        if b == 0x00 {
            if i == 0 {
                return None;
            }
            name_terminated = true;
        }
        if b != 0x00 && name_terminated {
            return None;
        }
    }

    let len_bytes: [u8; 4] = data[4 + entry_size - 4..4 + entry_size].try_into().unwrap();
    let first_len = if is_be {
        u32::from_be_bytes(len_bytes) as usize
    } else {
        u32::from_le_bytes(len_bytes) as usize
    };

    if first_len >= data.len() {
        return None;
    }

    Some(is_be)
}

fn detect_version(data: &[u8]) -> PacVersion {
    if is_valid_v1(data) {
        return PacVersion::Version1;
    }

    if let Some(is_be) = is_valid_v2_v3(data, 36) {
        return if is_be {
            PacVersion::Version2BE
        } else {
            PacVersion::Version2
        };
    }

    if let Some(is_be) = is_valid_v2_v3(data, 28) {
        return if is_be {
            PacVersion::Version3BE
        } else {
            PacVersion::Version3
        };
    }

    PacVersion::Unknown
}

fn parse_entries(data: &[u8], version: PacVersion) -> (Vec<PacEntry>, usize) {
    let mut entries = Vec::new();
    let is_be = matches!(version, PacVersion::Version2BE | PacVersion::Version3BE);

    let mut current_offset = match version {
        PacVersion::Version1 => 0,
        _ => 4, // Skip 4-byte count for V2/V3
    };

    let name_len = match version {
        PacVersion::Version1 => 252,
        PacVersion::Version2 | PacVersion::Version2BE => 32,
        PacVersion::Version3 | PacVersion::Version3BE => 24,
        PacVersion::Unknown => return (entries, 0),
    };

    let entry_size = name_len + 4;

    let num_files = match version {
        PacVersion::Version1 => 1024,
        _ => {
            let n = u32::from_le_bytes(data[0..4].try_into().unwrap());
            if is_be {
                n.swap_bytes() as usize
            } else {
                n as usize
            }
        }
    };

    for _ in 0..num_files {
        if current_offset + entry_size > data.len() {
            break;
        }

        let name_bytes = &data[current_offset..current_offset + name_len];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

        if name.is_empty() && version == PacVersion::Version1 {
            break;
        }

        let size_bytes: [u8; 4] = data[current_offset + name_len..current_offset + entry_size]
            .try_into()
            .unwrap();
        let size = if is_be {
            u32::from_be_bytes(size_bytes) as usize
        } else {
            u32::from_le_bytes(size_bytes) as usize
        };

        let data_offset = current_offset + entry_size;

        entries.push(PacEntry {
            name,
            original_offset: data_offset,
            original_size: size,
        });

        let actual_data_size = if version == PacVersion::Version1 {
            align_64(size)
        } else {
            size
        };
        current_offset += entry_size + actual_data_size;
    }

    (entries, current_offset)
}

pub fn build_patched_pac(original: &[u8], mod_files: &PacModFiles) -> Option<Vec<u8>> {
    let version = detect_version(original);
    if version == PacVersion::Unknown {
        debug_print!("[PAC] Unknown PAC version, aborting patch.");
        return None;
    }

    let is_be = matches!(version, PacVersion::Version2BE | PacVersion::Version3BE);
    let (entries, _) = parse_entries(original, version);
    if entries.is_empty() {
        return None;
    }

    let name_len = match version {
        PacVersion::Version1 => 252,
        PacVersion::Version2 | PacVersion::Version2BE => 32,
        PacVersion::Version3 | PacVersion::Version3BE => 24,
        _ => 0,
    };
    let entry_size = name_len + 4;

    let mut new_blobs: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut total_size = if version == PacVersion::Version1 {
        0
    } else {
        4
    };

    for (i, entry) in entries.iter().enumerate() {
        let search_name = entry.name.to_ascii_lowercase();
        let mut is_modded = false;

        if let Some(mod_path) = mod_files.replacements.get(&search_name)
            && let Ok(mod_data) = std::fs::read(mod_path)
        {
            debug_print!("[PAC] Replacing inner file: {}", entry.name);
            let actual_data_size = if version == PacVersion::Version1 {
                align_64(mod_data.len())
            } else {
                mod_data.len()
            };
            total_size += entry_size + actual_data_size;
            new_blobs.insert(i, mod_data);
            is_modded = true;
        }

        if !is_modded {
            let actual_data_size = if version == PacVersion::Version1 {
                align_64(entry.original_size)
            } else {
                entry.original_size
            };
            total_size += entry_size + actual_data_size;
        }
    }

    if new_blobs.is_empty() {
        let internal_names: Vec<&str> = entries.iter().take(5).map(|e| e.name.as_str()).collect();
        debug_print!(
            "[PAC] No matching mod files found. PAC contains names like: {:?}",
            internal_names
        );
        return None;
    }

    // Add dummy header at the end (is what FileEmulationFramework did)
    total_size += entry_size;

    let mut out = vec![0u8; total_size];
    let mut write_pos = 0;

    if version != PacVersion::Version1 {
        let count = entries.len() as u32;
        let count_bytes = if is_be {
            count.to_be_bytes()
        } else {
            count.to_le_bytes()
        };
        out[0..4].copy_from_slice(&count_bytes);
        write_pos += 4;
    }

    for (i, entry) in entries.iter().enumerate() {
        let is_modded = new_blobs.contains_key(&i);
        let blob_data = if is_modded {
            new_blobs.get(&i).unwrap().as_slice()
        } else {
            let end = entry.original_offset + entry.original_size;
            &original[entry.original_offset..end.min(original.len())]
        };

        let stored_size = blob_data.len() as u32;
        let actual_data_size = if version == PacVersion::Version1 {
            align_64(blob_data.len())
        } else {
            blob_data.len()
        };

        let name_bytes = entry.name.as_bytes();
        let copy_len = name_bytes.len().min(name_len);
        out[write_pos..write_pos + copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let size_bytes = if is_be {
            stored_size.to_be_bytes()
        } else {
            stored_size.to_le_bytes()
        };
        out[write_pos + name_len..write_pos + entry_size].copy_from_slice(&size_bytes);
        write_pos += entry_size;

        out[write_pos..write_pos + blob_data.len()].copy_from_slice(blob_data);
        write_pos += actual_data_size;
    }

    debug_print!("[PAC] Built patched PAC: {} bytes", out.len());
    Some(out)
}
