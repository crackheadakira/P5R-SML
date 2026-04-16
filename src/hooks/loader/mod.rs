pub mod loader_tick;
pub mod register_file;

pub fn register_all_loader_hooks(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    self::loader_tick::register_loader_tick_hook(memory)?;
    self::register_file::register_register_file_hook(memory)?;

    Ok(())
}
