use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub mod pac_builder;

use crate::pac::pac_builder::PacModFiles;
use crate::utils::logging::debug_print;

pub static PAC_MODS: Lazy<RwLock<HashMap<String, PacModFiles>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub fn on_mod_loading(mod_folder: &Path) {
    let redirector_pak = mod_folder.join("FEmulator/PAK");
    let redirector_pac = mod_folder.join("FEmulator/PAC"); // Just in case

    if redirector_pak.exists() {
        walk_pac_dirs(&redirector_pak);
    }
    if redirector_pac.exists() {
        walk_pac_dirs(&redirector_pac);
    }
}

fn walk_pac_dirs(dir: &Path) {
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

        if name.ends_with(".pac") || name.ends_with(".pak") || name.ends_with(".bin") {
            register_pac_dir(&path, &name);
        } else {
            walk_pac_dirs(&path);
        }
    }
}

fn register_pac_dir(pac_root: &Path, pac_name: &str) {
    let mut replacements = HashMap::new();

    // COMMAND.PAC/gui/image.gmd -> key is "gui/image.gmd"
    collect_files_recursive(pac_root, pac_root, &mut replacements);

    if !replacements.is_empty() {
        let mut lock = PAC_MODS.write().unwrap();
        let entry = lock.entry(pac_name.to_string()).or_insert(PacModFiles {
            replacements: HashMap::new(),
        });

        for (inner_path, file_path) in replacements {
            entry.replacements.insert(inner_path, file_path);
        }

        debug_print!(
            "[PAC LOADER] Registered {} files for {}",
            entry.replacements.len(),
            pac_name
        );
    }
}

fn collect_files_recursive(root: &Path, current: &Path, map: &mut HashMap<String, PathBuf>) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(root, &path, map);
        } else {
            if let Ok(rel_path) = path.strip_prefix(root) {
                let key = rel_path
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_ascii_lowercase();
                map.insert(key, path);
            }
        }
    }
}
