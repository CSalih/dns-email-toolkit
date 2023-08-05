use clap::Args;

#[derive(Args)]
pub struct Spf {
    /// Check if SPF syntax is valid
    #[arg(short, long)]
    pub check: bool,

    /// Use record value instead of querying it from DNS
    /// (useful for testing)
    #[arg(short, long)]
    pub record: Option<String>,

    /// Domain name to check
    pub domain: String,
}
