// Small canonical binary codec for audit records, in the same hand-rolled
// style as lifestream's object encoding. Strings and byte runs are length
// prefixed; integers are big-endian; options carry a one-byte present flag.

use crate::error::{Error, Result};

pub(crate) struct Writer {
    pub b: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { b: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    pub fn raw(&mut self, bytes: &[u8]) {
        self.b.extend_from_slice(bytes);
    }
    pub fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.b.extend_from_slice(s.as_bytes());
    }
    pub fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u64(x);
            }
            None => self.u8(0),
        }
    }
    pub fn opt_u32(&mut self, v: Option<u32>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u32(x);
            }
            None => self.u8(0),
        }
    }
}

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
    }
    fn need(&self, n: usize) -> Result<()> {
        if self.p + n > self.b.len() {
            return Err(Error::Corrupt("unexpected end of record".into()));
        }
        Ok(())
    }
    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    pub fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.b[self.p], self.b[self.p + 1]]);
        self.p += 2;
        Ok(v)
    }
    pub fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.b[self.p..self.p + 4]);
        self.p += 4;
        Ok(u32::from_be_bytes(a))
    }
    pub fn u64(&mut self) -> Result<u64> {
        self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.b[self.p..self.p + 8]);
        self.p += 8;
        Ok(u64::from_be_bytes(a))
    }
    pub fn arr16(&mut self) -> Result<[u8; 16]> {
        self.need(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.b[self.p..self.p + 16]);
        self.p += 16;
        Ok(a)
    }
    pub fn str(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        self.need(n)?;
        let s = String::from_utf8(self.b[self.p..self.p + n].to_vec())
            .map_err(|_| Error::Corrupt("string not utf8".into()))?;
        self.p += n;
        Ok(s)
    }
    pub fn opt_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.u64()?)),
        }
    }
    pub fn opt_u32(&mut self) -> Result<Option<u32>> {
        match self.u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.u32()?)),
        }
    }
}
