pub mod exists;
pub mod open;

pub fn register_all_io_hooks() -> Result<(), Box<dyn std::error::Error>> {
    self::exists::register_io_exists_hook()?;
    self::open::register_io_open_hook()?;

    Ok(())
}
