#[derive(Debug)]
pub enum SpfError {
    NoSpfRecordFound(String),
    CheckFailed(CheckError),
}

#[derive(Debug)]
pub struct CheckError {
    pub summary: String,
    pub description: String,
}

impl From<CheckError> for SpfError {
    fn from(err: CheckError) -> Self {
        Self::CheckFailed(err)
    }
}
