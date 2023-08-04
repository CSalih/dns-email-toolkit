use clap::Args;

#[derive(Args)]
pub struct Spf {
    /// Check if SPF syntax is valid
    #[arg(short, long)]
    pub check: bool,
    /// Domain name to check
    pub domain: String,
}
