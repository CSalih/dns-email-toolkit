mod use_case;
pub(in crate::spf) mod gateway;
mod presenter;


// TODO: we should export a Factorys instead of a concrete implementations
pub use self::use_case::{SummarySpfQuery, SummarySpfUseCase, SummarySpfUseCaseImpl};
pub use self::gateway::QueryTxtRecordGateway;
pub use self::presenter::SummarySpfTerminalPresenter;