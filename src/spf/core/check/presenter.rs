use crate::common::presenter::Presenter;
use crate::spf::core::check::use_case::SpfSummary;
use crate::spf::domain::{Mechanism, Term};

#[derive(Default)]
pub struct SummarySpfTerminalPresenter {}

impl SummarySpfTerminalPresenter {
    pub fn new() -> Self {
        SummarySpfTerminalPresenter::default()
    }
}

impl Presenter<SpfSummary, String> for SummarySpfTerminalPresenter {
    fn success(&mut self, data: SpfSummary) {
        println!("Raw Record: '{}'", data.raw_rdata);
        println!("SPF looks good");
    }
    fn error(&mut self, error: String) {
        eprintln!("Error: {:?}", error);
    }
}

#[derive(Default)]
pub struct SummarySpfWithDetailTerminalPresenter {}

impl SummarySpfWithDetailTerminalPresenter {
    pub fn new() -> Self {
        SummarySpfWithDetailTerminalPresenter::default()
    }
}

impl Presenter<SpfSummary, String> for SummarySpfWithDetailTerminalPresenter {
    fn success(&mut self, data: SpfSummary) {
        println!("Raw Record: '{}'", data.raw_rdata);

        // TODO: this should be enabled with a "detail" flag
        if !data.terms.is_empty() {
            Self::recursive_print("", &data.terms)
        }
    }
    fn error(&mut self, error: String) {
        eprintln!("Error: {:?}", error);
    }
}

impl SummarySpfWithDetailTerminalPresenter {
    fn recursive_print(indent: &str, terms: &[Term]) {
        terms.iter().for_each(|term| match term {
            Term::Directive(t) => {
                println!("{}- {}", indent, t);

                if let Mechanism::Include(i) = &t.mechanism {
                    let tabs = format!("{}\t", indent);

                    println!("{} Raw Record: {}", tabs, i.raw_rdata);
                    Self::recursive_print(&tabs, &i.terms);
                } else if let Mechanism::A(i) = &t.mechanism {
                    let tabs = format!("{}\t", indent);

                    let ip_addresses = if let Some(mask) = i.subnet_mask {
                        i.ip_addresses
                            .iter()
                            .map(|ip| format!("{}/{}", ip, mask))
                            .collect::<Vec<_>>()
                            .join(", ")
                    } else {
                        i.ip_addresses
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };

                    println!("{} IP: {}", tabs, ip_addresses);
                } else if let Mechanism::Mx(i) = &t.mechanism {
                    let tabs = format!("{}\t", indent);
                    let hosts = if let Some(mask) = i.subnet_mask {
                        i.hosts
                            .iter()
                            .map(|h| format!("{}/{}", h, mask))
                            .collect::<Vec<_>>()
                            .join(", ")
                    } else {
                        i.hosts.join(", ")
                    };

                    println!("{} MX: {}", tabs, &hosts);
                }
            }
            Term::Modifier(_) => {
                println!("{}- Modifier not implemented yet", indent);
            }
            Term::Unknown(u) => {
                println!("{}- Unknown term: {}", indent, u.raw_rdata);
            }
        });
    }
}
