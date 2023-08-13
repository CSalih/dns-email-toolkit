use clap::Args;

#[derive(Args)]
pub struct Spf {
    /// Output with details
    #[arg(short, long)]
    pub detail: bool,

    /// Use record value instead of querying it from DNS
    /// (useful for testing)
    #[arg(short, long)]
    pub record: Option<String>,

    /// Domain name to check
    pub domain: String,
}
