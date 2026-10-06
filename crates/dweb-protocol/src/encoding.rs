//! Canonical byte encoding used for hashing and signing.
//!
//! JSON is used on the wire for convenience, but every hash and signature is
//! computed over this binary form, so field order and whitespace never matter.
//! See `docs/SPEC.md` section "Canonical encoding".

use crate::error::{Error, Result};

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Fixed-size value (keys, hashes): raw bytes, no length.
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Variable-size value: u16 big-endian length, then the bytes.
    pub fn bytes(&mut self, b: &[u8]) -> Result<&mut Self> {
        let len: u16 = b
            .len()
            .try_into()
            .map_err(|_| Error::Encoding("field longer than 65535 bytes".into()))?;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(b);
        Ok(self)
    }

    pub fn str(&mut self, s: &str) -> Result<&mut Self> {
        self.bytes(s.as_bytes())
    }

    /// Option: 0x00 for none, 0x01 followed by the value for some.
    pub fn opt_fixed(&mut self, b: Option<&[u8]>) -> &mut Self {
        match b {
            None => self.u8(0),
            Some(b) => self.u8(1).fixed(b),
        }
    }

    pub fn opt_str(&mut self, s: Option<&str>) -> Result<&mut Self> {
        match s {
            None => Ok(self.u8(0)),
            Some(s) => self.u8(1).str(s),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
