use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::{marker::PhantomData, ops::Deref};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodingError {
    #[error("Missing data")]
    RanOutOfData,

    #[error("Invalid length")]
    InvalidLength,

    #[error("Invalid slice length")]
    InvalidSliceLength(#[from] TryFromSliceError),

    #[error("Unknown extension type {0:#x}")]
    UnknownExtensionType(u16),

    #[error("Shorter length required (expected <= {0}, actual = {1})")]
    LengthTooLarge(usize, usize),

    #[error("Longer length required. (expected >= {0}, actual = {1})")]
    LengthTooSmall(usize, usize),

    #[error("Invalid {0} enum value: {1}")]
    InvalidEnumValue(&'static str, usize),

    #[error("Duplicate server name types are prohibited in the SNI extension")]
    DuplicateServerNameType,
}

pub struct Reader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn consume(&mut self, n: usize) -> Result<&'a [u8], CodingError> {
        let slice = self.peek_slice(n)?;
        self.pos += n;
        Ok(slice)
    }

    pub fn peek(&self) -> Result<u8, CodingError> {
        if self.pos + 1 > self.buffer.len() {
            return Err(CodingError::RanOutOfData);
        }
        Ok(self.buffer[self.pos])
    }

    pub fn peek_slice(&self, n: usize) -> Result<&'a [u8], CodingError> {
        if self.pos + n > self.buffer.len() {
            return Err(CodingError::RanOutOfData);
        }
        Ok(&self.buffer[self.pos..self.pos + n])
    }

    pub fn is_consumed(&self) -> bool {
        self.pos == self.buffer.len()
    }

    pub fn bytes_consumed(&self) -> usize {
        self.pos
    }

    pub fn consume_rest(&mut self) -> &[u8] {
        if self.pos >= self.buffer.len() {
            return &[];
        }
        let slice = &self.buffer[self.pos..];
        self.pos = self.buffer.len();
        slice
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct u24(u32);

impl u24 {
    pub const MAX: u32 = 0xFFFFFF;

    pub fn new(value: u32) -> Option<Self> {
        (value <= Self::MAX).then_some(Self(value))
    }
}

impl From<u24> for usize {
    fn from(value: u24) -> Self {
        value.0 as Self
    }
}

impl VecLen for u24 {
    const BYTE_LEN: usize = 3;
    const MAX_LEN: usize = u24::MAX as usize;

    fn from_usize(value: usize) -> Result<Self, CodingError> {
        let value = u32::try_from(value).map_err(|_| CodingError::InvalidLength)?;
        u24::new(value).ok_or(CodingError::InvalidLength)
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0.to_be_bytes()[1..]);
    }
}

pub trait TlsCodable: Sized {
    fn write_to(&self, bytes: &mut Vec<u8>);
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError>;
    fn get_encoding(&self) -> Vec<u8> {
        let mut value = vec![];
        self.write_to(&mut value);
        value
    }
}

impl TlsCodable for u8 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.consume(1)?[0])
    }
}

impl TlsCodable for u16 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.consume(2)?.try_into().map(u16::from_be_bytes)?)
    }
}

impl TlsCodable for u24 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0.to_be_bytes()[1..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let slice = reader.consume(3)?;
        let bytes = [0, slice[0], slice[1], slice[2]];
        Ok(Self(u32::from_be_bytes(bytes)))
    }
}

impl TlsCodable for u32 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.consume(4)?.try_into().map(u32::from_be_bytes)?)
    }
}

impl<const N: usize> TlsCodable for [u8; N] {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self[..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.consume(N)?.try_into()?)
    }
}

pub trait VecLen: Debug + TlsCodable + Into<usize> {
    const BYTE_LEN: usize;
    const MAX_LEN: usize;

    fn from_usize(value: usize) -> Result<Self, CodingError>;
    fn encode_into_slice(&self, out: &mut [u8]);
}

impl VecLen for u8 {
    const BYTE_LEN: usize = 1;
    const MAX_LEN: usize = u8::MAX as usize;

    fn from_usize(value: usize) -> Result<Self, CodingError> {
        Self::try_from(value).map_err(|_| CodingError::InvalidLength)
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out[0] = *self;
    }
}

impl VecLen for u16 {
    const BYTE_LEN: usize = 2;
    const MAX_LEN: usize = u16::MAX as usize;

    fn from_usize(value: usize) -> Result<Self, CodingError> {
        Self::try_from(value).map_err(|_| CodingError::InvalidLength)
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
}

struct TlsListIter<'a, L: VecLen, T: TlsCodable> {
    reader: Reader<'a>,
    _l: PhantomData<L>,
    _t: PhantomData<T>,
}

impl<'a, L: VecLen, T: TlsCodable> TlsListIter<'a, L, T> {
    fn new(reader: &'a mut Reader) -> Result<Self, CodingError> {
        let len = L::read_from(reader).map(Into::into)?;
        Ok(Self {
            reader: Reader::new(reader.consume(len)?),
            _l: PhantomData,
            _t: PhantomData,
        })
    }
}

impl<'a, L: VecLen, T: TlsCodable> Iterator for TlsListIter<'a, L, T> {
    type Item = Result<T, CodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.reader.is_consumed()).then_some(T::read_from(&mut self.reader))
    }
}

pub trait Cardinality {
    const MIN_LEN: usize;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MaybeEmpty;
impl Cardinality for MaybeEmpty {
    const MIN_LEN: usize = 0;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmpty;
impl Cardinality for NonEmpty {
    const MIN_LEN: usize = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LengthPrefixedVec<L: VecLen, T: TlsCodable, C: Cardinality> {
    items: Vec<T>,
    _l: PhantomData<L>,
    _c: PhantomData<C>,
}

impl<L: VecLen, T: TlsCodable, C: Cardinality> LengthPrefixedVec<L, T, C> {
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }
}

pub trait Reconstrainable<L: VecLen, T: TlsCodable, C: Cardinality> {
    fn reconstrain(self) -> Result<LengthPrefixedVec<L, T, C>, CodingError>;
}

impl<L1, L2, T, C1, C2> Reconstrainable<L2, T, C2> for LengthPrefixedVec<L1, T, C1>
where
    L1: VecLen,
    L2: VecLen,
    T: TlsCodable,
    C1: Cardinality,
    C2: Cardinality,
{
    fn reconstrain(self) -> Result<LengthPrefixedVec<L2, T, C2>, CodingError> {
        if self.len() < C2::MIN_LEN {
            return Err(CodingError::LengthTooSmall(C2::MIN_LEN, self.len()));
        }
        if self.len() > L2::MAX_LEN {
            return Err(CodingError::LengthTooLarge(L2::MAX_LEN, self.len()));
        }
        Ok(LengthPrefixedVec::<L2, T, C2> {
            items: self.items,
            _l: PhantomData,
            _c: PhantomData,
        })
    }
}

impl<L: VecLen, T: TlsCodable, C: Cardinality> TlsCodable for LengthPrefixedVec<L, T, C> {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        let mut writer = LengthPrefixWriter::<L>::new(bytes);
        for item in &self.items {
            item.write_to(&mut writer);
        }
        writer.finalize_length_prefix();
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let items = TlsListIter::<L, T>::new(reader)?.collect::<Result<Vec<_>, _>>()?;
        if items.len() < C::MIN_LEN {
            return Err(CodingError::LengthTooSmall(C::MIN_LEN, items.len()));
        }
        Ok(Self {
            items,
            _l: PhantomData,
            _c: PhantomData,
        })
    }
}

impl<L: VecLen, T: TlsCodable, C: Cardinality> Deref for LengthPrefixedVec<L, T, C> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<L: VecLen, T: TlsCodable, C: Cardinality> TryFrom<Vec<T>> for LengthPrefixedVec<L, T, C> {
    type Error = CodingError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() < C::MIN_LEN {
            return Err(CodingError::LengthTooSmall(C::MIN_LEN, value.len()));
        }
        if value.len() > L::MAX_LEN {
            return Err(CodingError::LengthTooLarge(L::MAX_LEN, value.len()));
        }
        Ok(Self {
            items: value,
            _l: PhantomData,
            _c: PhantomData,
        })
    }
}

impl<T: TlsCodable> TlsCodable for Option<T> {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Some(value) = self {
            value.write_to(bytes)
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok((!reader.is_consumed()).then_some(T::read_from(reader)?))
    }
}

pub struct LengthPrefixWriter<'a, L: VecLen> {
    buf: &'a mut Vec<u8>,
    original_len: usize,
    finalized: bool,
    _l: PhantomData<L>,
}

impl<'a, L: VecLen> LengthPrefixWriter<'a, L> {
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        let original_len = buf.len();
        buf.resize(buf.len() + L::BYTE_LEN, 0);
        Self {
            buf,
            original_len,
            finalized: false,
            _l: PhantomData,
        }
    }

    pub fn finalize_length_prefix(mut self) {
        // This could fail if the encoded length exceeds MAX value of the uint L
        // However, this is the only place where write_to would currently need to
        // return a result. Will consider changing the return type to a Result later.
        let len = L::from_usize(self.buf.len() - self.original_len - L::BYTE_LEN).unwrap();
        len.encode_into_slice(&mut self.buf[self.original_len..self.original_len + L::BYTE_LEN]);
        self.finalized = true;
    }
}

impl<'a, L: VecLen> Drop for LengthPrefixWriter<'a, L> {
    fn drop(&mut self) {
        debug_assert!(
            self.finalized,
            "LengthPrefixWriter dropped without finalizing the length prefix"
        );
    }
}

impl<'a, L: VecLen> Deref for LengthPrefixWriter<'a, L> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        self.buf
    }
}

impl<'a, L: VecLen> DerefMut for LengthPrefixWriter<'a, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u24_prefixed_list() -> Result<(), CodingError> {
        let data = vec![0, 0, 4, 0, 2, 81, 8];
        let mut reader = Reader::new(&data);
        let list = LengthPrefixedVec::<u24, u16, NonEmpty>::read_from(&mut reader)?;
        assert_eq!(list[0], 2);
        assert_eq!(list[1], u16::from_be_bytes([81, 8]));
        assert_eq!(list.len(), 2);
        Ok(())
    }

    #[test]
    fn test_list_missing_data() -> Result<(), CodingError> {
        let data = vec![4, 0, 1, 8];
        let mut reader = Reader::new(&data);
        let result = LengthPrefixedVec::<u8, u16, NonEmpty>::read_from(&mut reader);
        assert!(matches!(result, Err(CodingError::RanOutOfData)));
        Ok(())
    }
}
