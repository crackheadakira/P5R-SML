use crate::{
    CpkBinding,
    utils::{SafeHandle, logging::debug_print},
};
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    fs::{self},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub struct ModFile {
    pub relative_path: String,
    pub absolute_path: PathBuf,

    pub relative_path_cstr: CString,
    pub absolute_path_cstr: CString,

    pub handle: Option<SafeHandle>,
    pub work_handle: Option<SafeHandle>,
    pub work_size: Option<i32>,
    pub binder_id: u32,
    pub is_bound: bool,
}

pub struct BinderCollection {
    pub binder_handles: HashSet<SafeHandle>,
    pub bindings: Vec<CpkBinding>,
    pub mod_files: HashMap<String, Arc<Mutex<ModFile>>>,
}

impl Default for BinderCollection {
    fn default() -> Self {
        Self::new()
    }
}

impl BinderCollection {
    pub fn new() -> Self {
        Self {
            binder_handles: HashSet::with_capacity(16),
            bindings: Vec::new(),
            mod_files: HashMap::new(),
        }
    }

    pub fn load_mod_folder(&mut self, mods_folder: &PathBuf) {
        let Ok(entries) = fs::read_dir(mods_folder) else {
            debug_print!("[MOD LOADER] Failed to read mods folder: {mods_folder:?}");
            return;
        };

        for entry in entries.flatten() {
            let mod_path = entry.path();
            if !mod_path.is_dir() {
                continue;
            }

            let config_path = mod_path.join("ModConfig.json");
            if !config_path.is_file() {
                debug_print!("[MOD LOADER] No ModConfig.json in {mod_path:?}, skipping");
                continue;
            }

            // Support both layouts just in case
            //   FEmulator/<type>/<relative_path>
            //   P5REssentials/CPK/<cpk_name>/<relative_path>
            let femulator_path = mod_path.join("FEmulator");
            if femulator_path.is_dir() {
                self.read_files_femulator(&femulator_path);
            }

            let essentials_cpk_path = mod_path.join("P5REssentials").join("CPK");
            if essentials_cpk_path.is_dir() {
                self.read_files_essentials_cpk(&essentials_cpk_path);
            }
        }
    }

    pub fn normalize_path(path: &str) -> String {
        path.replace('\\', "/")
            .to_lowercase()
            .trim_start_matches('/')
            .to_string()
    }

    pub fn find_mod_file_by_relative_path(
        &self,
        target_path: &str,
    ) -> Option<&Arc<Mutex<ModFile>>> {
        self.mod_files.get(&Self::normalize_path(target_path))
    }

    pub fn file_is_mod(&self, target_path: &str) -> bool {
        self.mod_files
            .contains_key(&Self::normalize_path(target_path))
    }

    pub fn get_handle_for_path(&self, path: &str) -> Option<SafeHandle> {
        if let Some(mod_file_arc) = self.mod_files.get(&Self::normalize_path(path))
            && let Ok(mod_file) = mod_file_arc.lock()
        {
            for binding in &self.bindings {
                if binding.bind_id == mod_file.binder_id {
                    return Some(binding.work_mem_ptr());
                }
            }
        }
        None
    }

    /// Walks `FEmulator/<type>/...` — drops the first component (e.g. "SPD",
    /// "CRI") and skips the SPD subtree which is handled by the SPD emulator.
    fn read_files_femulator(&mut self, femulator_path: &Path) {
        let Ok(type_entries) = fs::read_dir(femulator_path) else {
            return;
        };

        for type_entry in type_entries.flatten() {
            let type_path = type_entry.path();
            if !type_path.is_dir() {
                continue;
            }

            let type_name = type_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_uppercase();

            if type_name == "SPD" || type_name == "PAK" || type_name == "PAC" {
                continue;
            }

            self.read_files_recursive(&type_path, &type_path);
        }
    }

    /// Walks `P5REssentials/CPK/<cpk_name>/<relative_path>`.
    /// Strips the CPK name so the relative path seen by CRI is just
    /// `<relative_path>` (e.g. `FONT/FONT0.FNT`, `BATTLE/GUI/BKSK_P_BC0001.DDS`).
    ///
    /// Packed CPK files (where the CPK name itself is the mod, e.g. `MOD.CPK`)
    /// are detected by checking whether the immediate children of the CPK name
    /// directory look like a real file tree (i.e. contain files/dirs) vs a
    /// single packed file. In practice, if the directory directly contains a
    /// `.cpk` file rather than loose files, we skip it — it needs to be bound
    /// as a CPK, not as loose files, which is outside our current scope.
    fn read_files_essentials_cpk(&mut self, cpk_root: &Path) {
        let Ok(cpk_entries) = fs::read_dir(cpk_root) else {
            return;
        };

        for cpk_entry in cpk_entries.flatten() {
            let cpk_name_dir = cpk_entry.path();
            if !cpk_name_dir.is_dir() {
                continue;
            }

            let cpk_name = cpk_name_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_uppercase();

            let has_loose_files = fs::read_dir(&cpk_name_dir)
                .map(|entries| {
                    entries.flatten().any(|e| {
                        let p = e.path();
                        if p.is_dir() {
                            return true;
                        }
                        // A file that isn't a .cpk is a loose file.
                        p.extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| !ext.eq_ignore_ascii_case("cpk"))
                            .unwrap_or(true)
                    })
                })
                .unwrap_or(false);

            if !has_loose_files {
                debug_print!(
                    "[MOD LOADER] Skipping P5REssentials CPK '{cpk_name}' — appears to be a packed CPK, not loose files"
                );
                continue;
            }

            debug_print!("[MOD LOADER] Loading P5REssentials loose files from CPK '{cpk_name}'");

            self.read_files_recursive(&cpk_name_dir, &cpk_name_dir);
        }
    }

    fn read_files_recursive(&mut self, path: &Path, base_path: &Path) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();

            if entry_path.is_dir() {
                self.read_files_recursive(&entry_path, base_path);
                continue;
            }

            if !entry_path.is_file() {
                continue;
            }

            // Skip packed CPK files, no separate bind handling yet
            if entry_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("cpk"))
                .unwrap_or(false)
            {
                debug_print!(
                    "[MOD LOADER] Skipping packed CPK file: {}",
                    entry_path.display()
                );
                continue;
            }

            let Ok(rel_path) = entry_path.strip_prefix(base_path) else {
                continue;
            };
            let normalized = Self::normalize_path(&rel_path.to_string_lossy());

            let Ok(relative_cstr) = CString::new(normalized.clone()) else {
                debug_print!("[MOD LOADER] Invalid path (null byte): {normalized}");
                continue;
            };
            let Ok(absolute_cstr) = CString::new(entry_path.to_string_lossy().as_bytes()) else {
                debug_print!(
                    "[MOD LOADER] Invalid absolute path: {}",
                    entry_path.display()
                );
                continue;
            };

            let mod_file = ModFile {
                relative_path: normalized.clone(),
                absolute_path: entry_path.clone(),
                relative_path_cstr: relative_cstr,
                absolute_path_cstr: absolute_cstr,
                handle: None,
                binder_id: 0,
                is_bound: false,
                work_handle: None,
                work_size: None,
            };

            debug_print!(
                "[MOD LOADER] Added mod file: {} (from: {})",
                mod_file.relative_path,
                mod_file.absolute_path.display()
            );

            self.mod_files
                .insert(normalized, Arc::new(Mutex::new(mod_file)));
        }
    }
}
