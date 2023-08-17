use std::error::Error;

pub trait CliCommand<T> {
    fn execute(&self) -> Result<(), Box<dyn Error>>;
}
