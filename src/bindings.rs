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
    pub relative_path: PathBuf,
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
    pub mod_files: HashMap<PathBuf, Arc<Mutex<ModFile>>>,
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
        // get all mod_data inside of folders, then recursively read them
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

    pub fn normalize_path(path: &Path) -> PathBuf {
        let mut s = path.to_string_lossy().replace('\\', "/").to_lowercase();
        if s.starts_with('/') {
            s.remove(0);
        }
        PathBuf::from(s)
    }

    pub fn sanitize_cri_path(path: &str) -> String {
        let mut s = path.replace('\\', "/").to_lowercase();
        if s.starts_with('/') {
            s.remove(0);
        }
        s
    }

    pub fn normalized_path_from_string(path: &str) -> PathBuf {
        let s = path.replace('\\', "/");
        PathBuf::from(s)
    }

    pub fn find_mod_file_by_relative_path(
        &self,
        target_path: &Path,
    ) -> Option<&Arc<Mutex<ModFile>>> {
        self.mod_files.values().find(|mod_file_arc| {
            if let Ok(mod_file) = mod_file_arc.lock() {
                mod_file.relative_path == target_path
            } else {
                false
            }
        })
    }

    pub fn get_handle_for_path(&self, path: &PathBuf) -> Option<SafeHandle> {
        if let Some(mod_file_arc) = self.mod_files.get(path)
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

    pub fn file_is_mod(&self, path: &PathBuf) -> bool {
        self.mod_files.contains_key(path)
    }

    fn read_files_recursive(&mut self, path: &PathBuf, base_path: &PathBuf) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Ok(rel_path) = entry_path.strip_prefix(base_path) {
                        let mut components = rel_path.components();
                        components.next();

                        let stripped_rel_path = components.as_path();

                        let mod_file = ModFile {
                            relative_path: Self::normalize_path(stripped_rel_path),
                            absolute_path: Self::normalize_path(&entry_path),
                            handle: None,
                            binder_id: 0,
                            is_bound: false,
                            work_handle: None,
                            work_size: None,
                        };

                        debug_print(&format!(
                            "[MOD LOADER] Added mod folder: {} (from file: {})",
                            mod_file.relative_path.display(),
                            mod_file.absolute_path.display()
                        ));

                        self.mod_files.insert(
                            Self::normalize_path(stripped_rel_path),
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
