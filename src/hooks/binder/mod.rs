mod bind_cpk;
mod bind_file;
mod bind_files;
mod find;
mod get_size_for_bind_files;
mod get_status;
mod set_priority;
mod unbind;

pub use bind_cpk::cri_binder_bind_cpk_hook;
pub use bind_file::cri_binder_bind_file_hook;
pub use bind_files::cri_binder_bind_files_hook;
pub use find::cri_binder_find_hook;
pub use get_size_for_bind_files::cri_binder_get_size_for_bind_files_hook;
pub use get_status::{CriBinderStatus, cri_binder_get_status_hook};
pub use set_priority::cri_binder_set_priority_hook;
pub use unbind::cri_binder_unbind_hook;

pub fn register_all_binder_hooks(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    self::bind_cpk::register_bind_cpk_hook(memory)?;
    self::bind_file::register_bind_file_hook(memory)?;
    self::bind_files::register_bind_files_hook(memory)?;
    self::unbind::register_unbind_hook(memory)?;
    self::find::register_find_hook(memory)?;
    self::get_size_for_bind_files::register_get_size_for_bind_files_hook(memory)?;
    self::get_status::register_get_status_hook(memory)?;
    self::set_priority::register_set_priority_hook(memory)?;

    Ok(())
}
