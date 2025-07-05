use thiserror::Error;

#[derive(Error, Debug)]
pub enum VotpError {
    #[error("key file is empty")]
    EmptyKey,
}
