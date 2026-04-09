use crate::{
    CpkBinding,
    utils::{SafeHandle, logging::debug_print},
};
use std::{
    collections::{HashMap, HashSet},
    fs::{self},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use winapi::shared::minwindef::DWORD;

pub struct ModFile {
    pub relative_path: String,
    pub absolute_path: PathBuf,
    pub handle: Option<SafeHandle>,
    pub work_handle: Option<SafeHandle>,
    pub work_size: Option<i32>,
    pub binder_id: DWORD,
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
        if let Ok(entries) = fs::read_dir(mods_folder) {
            for entry in entries.flatten() {
                let mod_path = entry.path();
                if mod_path.is_dir() {
                    let mod_data_path = mod_path.join("mod_data");
                    if mod_data_path.is_dir() {
                        self.read_files_recursive(&mod_data_path, &mod_data_path);
                    } else {
                        debug_print(&format!(
                            "[MOD LOADER] mod_data folder not found at {mod_data_path:?}, skipping"
                        ));
                    }
                }
            }
        } else {
            debug_print(&format!(
                "[MOD LOADER] Failed to read mods folder: {mods_folder:?}"
            ));
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
        if let Some(mod_file_arc) = self.mod_files.get(&Self::normalize_path(path)) {
            if let Ok(mod_file) = mod_file_arc.lock() {
                for binding in &self.bindings {
                    if binding.bind_id == mod_file.binder_id {
                        return Some(binding.work_mem_ptr());
                    }
                }
            }
        }
        None
    }

    fn read_files_recursive(&mut self, path: &Path, base_path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Ok(rel_path) = entry_path.strip_prefix(base_path) {
                        let mod_file = ModFile {
                            relative_path: Self::normalize_path(&rel_path.to_string_lossy()),
                            absolute_path: entry_path.clone(),
                            handle: None,
                            binder_id: 0,
                            is_bound: false,
                            work_handle: None,
                            work_size: None,
                        };

                        debug_print(&format!(
                            "[MOD LOADER] Added mod file: {} (from: {})",
                            mod_file.relative_path,
                            mod_file.absolute_path.display()
                        ));

                        self.mod_files.insert(
                            mod_file.relative_path.clone(),
                            Arc::new(Mutex::new(mod_file)),
                        );
                    }
                } else if entry_path.is_dir() {
                    self.read_files_recursive(&entry_path, base_path);
                }
            }
        }
    }
}
