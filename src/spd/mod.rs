use crate::debug_print;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub mod hook_spd_tick;
pub mod spd_builder;

pub static SPD_MODS: Lazy<Mutex<HashMap<String, SpdMod>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub struct SpdMod {
    pub dds_files: Vec<PathBuf>,
    pub spdspr_files: Vec<PathBuf>,
}

pub fn on_mod_loading(mod_folder: &Path) {
    let redirector = mod_folder.join("FEmulator/SPD");
    if !redirector.exists() {
        return;
    }
    walk_spd_dirs(&redirector);
}

fn walk_spd_dirs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
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
            register_spd_dir(&path, &name);
        } else {
            walk_spd_dirs(&path);
        }
    }
}

fn register_spd_dir(dir: &Path, key: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
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

    debug_print!(
        "[SPD] Registered {} dds + {} spdspr for '{key}'",
        dds_files.len(),
        spdspr_files.len()
    );

    let mut mods = SPD_MODS.lock().unwrap();
    let entry = mods.entry(key.to_string()).or_insert_with(|| SpdMod {
        dds_files: Vec::new(),
        spdspr_files: Vec::new(),
    });
    entry.dds_files.extend(dds_files);
    entry.spdspr_files.extend(spdspr_files);
}
