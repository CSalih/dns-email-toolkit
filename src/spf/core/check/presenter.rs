use crate::common::presenter::Presenter;
use crate::spf::core::check::use_case::SpfSummary;
use crate::spf::domain::{Mechanism, Modifier, SpfError, SyntaxError, Term};

#[derive(Default)]
pub struct SummarySpfTerminalPresenter {}

impl SummarySpfTerminalPresenter {
    pub fn new() -> Self {
        SummarySpfTerminalPresenter::default()
    }
}

impl Presenter<SpfSummary, SpfError> for SummarySpfTerminalPresenter {
    fn success(&mut self, data: &SpfSummary) {
        println!("Raw Record: '{}'", data.raw_rdata);
        println!("SPF looks good");
    }
    fn error(&mut self, error: &SpfError) {
        print_spf_error(error);
    }
}

#[derive(Default)]
pub struct SummarySpfWithDetailTerminalPresenter {}

impl SummarySpfWithDetailTerminalPresenter {
    pub fn new() -> Self {
        SummarySpfWithDetailTerminalPresenter::default()
    }
}

impl Presenter<SpfSummary, SpfError> for SummarySpfWithDetailTerminalPresenter {
    fn success(&mut self, data: &SpfSummary) {
        println!("Raw Record: '{}'", data.raw_rdata);

        // TODO: this should be enabled with a "detail" flag
        if !data.terms.is_empty() {
            Self::recursive_print("", &data.terms)
        }
    }
    fn error(&mut self, error: &SpfError) {
        print_spf_error(error);
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
                } else if let Mechanism::Ip4(i) = &t.mechanism {
                    let tabs = format!("{}\t", indent);
                    let ip_address = if let Some(mask) = i.subnet_mask {
                        format!("{}/{}", i.ip_address, mask)
                    } else {
                        i.ip_address.to_string()
                    };

                    println!("{} IPv4: {}", tabs, &ip_address);
                } else if let Mechanism::Ip6(i) = &t.mechanism {
                    let tabs = format!("{}\t", indent);
                    let ip_address = if let Some(mask) = i.subnet_mask {
                        format!("{}/{}", i.ip_address, mask)
                    } else {
                        i.ip_address.to_string()
                    };

                    println!("{} IPv6: {}", tabs, &ip_address);
                }
            }
            Term::Modifier(m) => {
                println!("{}- {}", indent, m);

                if let Modifier::Redirect(r) = &m {
                    let tabs = format!("{}\t", indent);

                    println!("{}Raw Record: {}", tabs, r.raw_rdata);
                    Self::recursive_print(&tabs, &r.terms);
                } else {
                    println!("{}- Modifier '{}' not implemented yet", indent, m);
                }
            }
            Term::Unknown(u) => {
                println!("{}- Unknown term: {}", indent, u.raw_rdata);
            }
        });
    }
}

fn print_spf_error(error: &SpfError) {
    match error {
        SpfError::NoSpfRecordFound(message) => {
            eprintln!("Error: {}", message);
        }
        SpfError::CheckFailed(err) => {
            eprintln!("Check failed: {}", err.summary);
            eprintln!("\t {}", err.description);
        }
        SpfError::SyntaxError(err) => {
            let report: miette::Report = (*err).clone().into();
            eprintln!("{:?}", report);
        }
    }
}

impl From<SyntaxError> for miette::Report {
    fn from(err: SyntaxError) -> Self {
        let mut diag = miette::MietteDiagnostic::new(err.message.to_string());
        if let Some(help) = err.help {
            diag = diag.with_help(help);
        }
        if let Some(src_labels) = err.src_labels {
            diag = diag.with_labels(src_labels);
        }
        if let Some(severity) = err.severity {
            diag = diag.with_severity(severity);
        }
        let mut report = miette::Report::from(diag);
        if let Some(src) = err.src {
            report = report.with_source_code(src)
        }
        report
    }
}
