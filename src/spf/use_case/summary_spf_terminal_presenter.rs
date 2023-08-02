use crate::common::presenter::Presenter;
use crate::spf::domain::model::Term;
use crate::spf::use_case::summary_spf::SpfSummary;

pub struct SummarySpfTerminalPresenter {}

impl SummarySpfTerminalPresenter {
    pub fn new() -> Self {
        SummarySpfTerminalPresenter {}
    }
}

impl Presenter<SpfSummary, String> for SummarySpfTerminalPresenter {
    fn success(&mut self, data: SpfSummary) {
        println!("Raw Record: '{}'", data.raw_rdata);
        println!("SPF Version: {}", data.version);

        if !data.terms.is_empty() {
            println!("Found following terms:");
            data.terms.iter().for_each(|term| match term {
                Term::Directive(t) => {
                    println!("\t- {}", t);
                }
                Term::Modifier(_) => {
                    println!("\t- Modifier not implemented yet");
                }
            });
        }
    }
    fn error(&mut self, error: String) {
        eprintln!("Error: {:?}", error);
    }
}
