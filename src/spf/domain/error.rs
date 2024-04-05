#[derive(Debug)]
pub enum SpfError {
    NoSpfRecordFound(String),
    CheckFailed(CheckError),
    SyntaxError(SyntaxError),
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

pub type LabelSpan = miette::LabeledSpan;
pub type Severity = miette::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub message: String,
    pub severity: Option<Severity>,
    pub src: Option<String>,
    pub src_labels: Option<Vec<LabelSpan>>,
    pub help: Option<String>,
    pub code: Option<String>,
    pub code_url: Option<String>,
}

impl From<SyntaxError> for SpfError {
    fn from(err: SyntaxError) -> Self {
        Self::SyntaxError(err)
    }
}

impl SyntaxError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            severity: None,
            src: None,
            src_labels: None,
            help: None,
            code: None,
            code_url: None,
        }
    }

    pub fn with_src(mut self, code: impl Into<String>) -> Self {
        self.src = Some(code.into());
        self
    }

    pub fn with_src_labels(mut self, labels: impl IntoIterator<Item = LabelSpan>) -> Self {
        self.src_labels = Some(labels.into_iter().collect());
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_code(mut self, code: impl Into<String>, url: Option<impl Into<String>>) -> Self {
        self.code = Some(code.into());
        if let Some(url) = url {
            self.code_url = Some(url.into());
        }
        self
    }
    pub fn with_code_url(mut self, url: impl Into<String>) -> Self {
        self.code_url = Some(url.into());
        self
    }
}
