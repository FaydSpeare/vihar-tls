use std::fmt::Debug;
use std::ops::DerefMut;
use std::{marker::PhantomData, ops::Deref};

use crate::errors::{DecodingError, InvalidEncodingError};

pub struct Reader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn consume(&mut self, n: usize) -> Result<&'a [u8], DecodingError> {
        let slice = self.peek_slice(n)?;
        self.pos += n;
        Ok(slice)
    }

    pub fn peek(&self) -> Result<u8, DecodingError> {
        if self.pos + 1 > self.buffer.len() {
            return Err(DecodingError::RanOutOfData);
        }
        Ok(self.buffer[self.pos])
    }

    pub fn peek_slice(&self, n: usize) -> Result<&'a [u8], DecodingError> {
        if self.pos + n > self.buffer.len() {
            return Err(DecodingError::RanOutOfData);
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

    fn from_usize(value: usize) -> Result<Self, String> {
        let value = u32::try_from(value).map_err(|_| "invalid length".to_string())?;
        u24::new(value).ok_or("invalid length".into())
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0.to_be_bytes()[1..]);
    }
}

pub trait TlsCodable: Sized {
    fn write_to(&self, bytes: &mut Vec<u8>);
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError>;
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

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(reader.consume(1)?[0])
    }
}

impl TlsCodable for bool {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        let value = if *self { 1u8 } else { 0u8 };
        value.write_to(bytes);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(1 == u8::read_from(reader)?)
    }
}

impl TlsCodable for u16 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let bytes: [u8; 2] = reader.consume(2)?.try_into().unwrap();
        Ok(u16::from_be_bytes(bytes))
    }
}

impl TlsCodable for u24 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0.to_be_bytes()[1..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let slice = reader.consume(3)?;
        let bytes = [0, slice[0], slice[1], slice[2]];
        Ok(Self(u32::from_be_bytes(bytes)))
    }
}

impl TlsCodable for u32 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let bytes: [u8; 4] = reader.consume(4)?.try_into().unwrap();
        Ok(u32::from_be_bytes(bytes))
    }
}

impl<const N: usize> TlsCodable for [u8; N] {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self[..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        Ok(reader.consume(N)?.try_into().unwrap())
    }
}

pub trait VecLen: Debug + TlsCodable + Into<usize> {
    const BYTE_LEN: usize;
    const MAX_LEN: usize;

    fn from_usize(value: usize) -> Result<Self, String>;
    fn encode_into_slice(&self, out: &mut [u8]);
}

impl VecLen for u8 {
    const BYTE_LEN: usize = 1;
    const MAX_LEN: usize = u8::MAX as usize;

    fn from_usize(value: usize) -> Result<Self, String> {
        Self::try_from(value).map_err(|_| "invalid length".into())
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out[0] = *self;
    }
}

impl VecLen for u16 {
    const BYTE_LEN: usize = 2;
    const MAX_LEN: usize = u16::MAX as usize;

    fn from_usize(value: usize) -> Result<Self, String> {
        Self::try_from(value).map_err(|_| "invalid length".into())
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
    fn new(reader: &'a mut Reader) -> Result<Self, DecodingError> {
        let len = L::read_from(reader).map(Into::into)?;
        Ok(Self {
            reader: Reader::new(reader.consume(len)?),
            _l: PhantomData,
            _t: PhantomData,
        })
    }
}

impl<L: VecLen, T: TlsCodable> Iterator for TlsListIter<'_, L, T> {
    type Item = Result<T, DecodingError>;

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
    fn reconstrain(self) -> Result<LengthPrefixedVec<L, T, C>, InvalidEncodingError>;
}

impl<L1, L2, T, C1, C2> Reconstrainable<L2, T, C2> for LengthPrefixedVec<L1, T, C1>
where
    L1: VecLen,
    L2: VecLen,
    T: TlsCodable,
    C1: Cardinality,
    C2: Cardinality,
{
    fn reconstrain(self) -> Result<LengthPrefixedVec<L2, T, C2>, InvalidEncodingError> {
        if self.len() < C2::MIN_LEN {
            return Err(InvalidEncodingError::LengthTooSmall(
                C2::MIN_LEN,
                self.len(),
            ));
        }
        if self.len() > L2::MAX_LEN {
            return Err(InvalidEncodingError::LengthTooLarge(
                L2::MAX_LEN,
                self.len(),
            ));
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

    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        let items = TlsListIter::<L, T>::new(reader)?.collect::<Result<Vec<_>, _>>()?;
        if items.len() < C::MIN_LEN {
            return Err(InvalidEncodingError::LengthTooSmall(C::MIN_LEN, items.len()).into());
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
    type Error = InvalidEncodingError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() < C::MIN_LEN {
            return Err(InvalidEncodingError::LengthTooSmall(
                C::MIN_LEN,
                value.len(),
            ));
        }
        if value.len() > L::MAX_LEN {
            return Err(InvalidEncodingError::LengthTooLarge(
                L::MAX_LEN,
                value.len(),
            ));
        }
        Ok(Self {
            items: value,
            _l: PhantomData,
            _c: PhantomData,
        })
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

impl<L: VecLen> Drop for LengthPrefixWriter<'_, L> {
    fn drop(&mut self) {
        debug_assert!(
            self.finalized,
            "LengthPrefixWriter dropped without finalizing the length prefix"
        );
    }
}

impl<L: VecLen> Deref for LengthPrefixWriter<'_, L> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        self.buf
    }
}

impl<L: VecLen> DerefMut for LengthPrefixWriter<'_, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
    }
}

impl<T: TlsCodable> TlsCodable for Option<T> {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        if let Some(value) = self {
            1u8.write_to(bytes);
            value.write_to(bytes);
        } else {
            0u8.write_to(bytes);
        }
    }
    fn read_from(reader: &mut Reader) -> Result<Self, DecodingError> {
        if u8::read_from(reader)? == 0 {
            return Ok(None);
        }
        Ok(Some(T::read_from(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u24_prefixed_list() -> Result<(), DecodingError> {
        let data = vec![0, 0, 4, 0, 2, 81, 8];
        let mut reader = Reader::new(&data);
        let list = LengthPrefixedVec::<u24, u16, NonEmpty>::read_from(&mut reader)?;
        assert_eq!(list[0], 2);
        assert_eq!(list[1], u16::from_be_bytes([81, 8]));
        assert_eq!(list.len(), 2);
        Ok(())
    }

    #[test]
    fn test_list_missing_data() -> Result<(), DecodingError> {
        let data = vec![4, 0, 1, 8];
        let mut reader = Reader::new(&data);
        let result = LengthPrefixedVec::<u8, u16, NonEmpty>::read_from(&mut reader);
        assert!(matches!(result, Err(DecodingError::RanOutOfData)));
        Ok(())
    }

    #[test]
    fn test_list_data_too_long() -> Result<(), DecodingError> {
        let data = vec![4, 0, 1, 2, 3, 4];
        let mut reader = Reader::new(&data);
        let _result = LengthPrefixedVec::<u8, u8, NonEmpty>::read_from(&mut reader)?;
        Ok(())
    }
}
