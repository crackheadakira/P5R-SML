pub mod exists;
pub mod open;

pub fn register_all_io_hooks(memory: &'static [u8]) -> Result<(), Box<dyn std::error::Error>> {
    self::exists::register_io_exists_hook(memory)?;
    self::open::register_io_open_hook(memory)?;

    Ok(())
}
