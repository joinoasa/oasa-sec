use std::fmt;

/// Errors from OASA-SEC operations.
#[derive(Debug)]
pub enum Error {
    /// Reading or writing a file or socket failed.
    Io(std::io::Error),
    /// The Noise handshake or an encrypted message failed. Treat this as a
    /// possible attack: the peer is not who it claims, or the data was changed.
    Noise(snow::Error),
    /// A pairing code is malformed, has a bad checksum, or is the wrong version.
    BadCode(&'static str),
    /// A stored key or trust file is malformed or has unsafe permissions.
    BadKeyFile(String),
    /// The peer broke the pairing protocol.
    Protocol(&'static str),
    /// The encrypted link was set up wrongly (bad settings, a peer that can't
    /// be added).
    Link(&'static str),
    /// A public key that is a small-order point (zero, one and the like). No
    /// real device has one, and a Diffie-Hellman with it proves nothing.
    SmallOrderKey,
    /// The key is in this device's `removed` file (R-SEC2). Only a person at
    /// the device can undo that, with `oasa-pair restore`.
    Removed,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Noise(e) => write!(f, "encryption or authentication failed: {e}"),
            Error::BadCode(why) => write!(f, "bad pairing code: {why}"),
            Error::BadKeyFile(why) => write!(f, "bad key file: {why}"),
            Error::Protocol(why) => write!(f, "pairing protocol error: {why}"),
            Error::Link(why) => write!(f, "link error: {why}"),
            Error::SmallOrderKey => write!(f, "that public key is not a valid device key"),
            Error::Removed => write!(
                f,
                "that device was removed here; a removed device must make a new identity and pair again (or run `oasa-pair restore` on this device)"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Noise(e)
    }
}
