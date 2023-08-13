pub enum Modifier {
    Exp(ExpModifier),
    Redirect(RedirectModifier),
}

impl Modifier {
    pub(crate) fn need_lookup(&self) -> bool {
        matches!(self, Modifier::Redirect(_))
    }
}

pub struct ExpModifier {
    pub raw_value: String,
}

pub struct RedirectModifier {
    pub domain_spec: String,
}
