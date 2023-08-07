pub(in crate::spf) mod gateway;
mod presenter;
mod use_case;

// TODO: we should export a Factorys instead of a concrete implementations
pub use self::gateway::QueryTxtRecordGateway;
pub use self::presenter::SummarySpfTerminalPresenter;
pub use self::use_case::{SummarySpfQuery, SummarySpfUseCase, SummarySpfUseCaseImpl};
