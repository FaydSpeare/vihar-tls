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

    #[error("Length exceeds allowed value")]
    LengthTooLarge,
}

pub struct Reader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&[u8], CodingError> {
        if self.pos + n > self.buffer.len() {
            return Err(CodingError::RanOutOfData);
        }

        let slice = &self.buffer[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn consumed(&self) -> bool {
        self.pos == self.buffer.len()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct u24(u32);

impl u24 {
    pub const MAX: u32 = 0xFFFFFF;
}

impl From<u24> for usize {
    fn from(value: u24) -> Self {
        value.0 as Self
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
        Ok(reader.take(1)?[0])
    }
}

impl TlsCodable for u16 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.take(2)?.try_into().map(u16::from_be_bytes)?)
    }
}

impl TlsCodable for u24 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0.to_be_bytes()[1..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let slice = reader.take(3)?;
        let bytes = [0, slice[0], slice[1], slice[2]];
        Ok(Self(u32::from_be_bytes(bytes)))
    }
}

impl TlsCodable for u32 {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.take(4)?.try_into().map(u32::from_be_bytes)?)
    }
}

impl<const N: usize> TlsCodable for [u8; N] {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self[..]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        Ok(reader.take(N)?.try_into()?)
    }
}

pub trait ListLen: TlsCodable + Into<usize> {
    const SIZE: usize;
    fn from_usize(value: usize) -> Result<Self, CodingError>;
    fn encode_into_slice(&self, out: &mut [u8]);
}

impl ListLen for u8 {
    const SIZE: usize = 1;
    fn from_usize(value: usize) -> Result<Self, CodingError> {
        Self::try_from(value).map_err(|_| CodingError::InvalidLength)
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out[0] = *self;
    }
}

impl ListLen for u16 {
    const SIZE: usize = 2;
    fn from_usize(value: usize) -> Result<Self, CodingError> {
        Self::try_from(value).map_err(|_| CodingError::InvalidLength)
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
}

impl ListLen for u24 {
    const SIZE: usize = 3;
    fn from_usize(value: usize) -> Result<Self, CodingError> {
        let value = u32::try_from(value).map_err(|_| CodingError::InvalidLength)?;
        if value > Self::MAX {
            return Err(CodingError::InvalidLength);
        }
        Ok(u24(value))
    }
    fn encode_into_slice(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0.to_be_bytes()[1..]);
    }
}

struct TlsListIter<'a, L: ListLen, T: TlsCodable> {
    reader: Reader<'a>,
    _l: PhantomData<L>,
    _t: PhantomData<T>,
}

impl<'a, L: ListLen, T: TlsCodable> TlsListIter<'a, L, T> {
    fn new(reader: &'a mut Reader) -> Result<Self, CodingError> {
        let len = L::read_from(reader).map(Into::into)?;
        Ok(Self {
            reader: Reader::new(reader.take(len)?),
            _l: PhantomData,
            _t: PhantomData,
        })
    }
}

impl<'a, L: ListLen, T: TlsCodable> Iterator for TlsListIter<'a, L, T> {
    type Item = Result<T, CodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.reader.consumed()).then_some(T::read_from(&mut self.reader))
    }
}

#[derive(Debug)]
pub struct TlsList<L: ListLen, T: TlsCodable> {
    items: Vec<T>,
    _l: PhantomData<L>,
}

impl<L: ListLen, T: TlsCodable> TlsCodable for TlsList<L, T> {
    fn write_to(&self, bytes: &mut Vec<u8>) {
        let len_range = bytes.len()..bytes.len() + L::SIZE;
        bytes.resize(bytes.len() + L::SIZE, 0); // placeholder for length

        let original_len = bytes.len();
        for item in &self.items {
            item.write_to(bytes);
        }

        let encoded_len = bytes.len() - original_len;
        let len = L::from_usize(encoded_len).unwrap();
        len.encode_into_slice(&mut bytes[len_range]);
    }

    fn read_from(reader: &mut Reader) -> Result<Self, CodingError> {
        let items = TlsListIter::<L, T>::new(reader)?.collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            items,
            _l: PhantomData,
        })
    }
}

impl<L: ListLen, T: TlsCodable> Deref for TlsList<L, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<L: ListLen, T: TlsCodable> DerefMut for TlsList<L, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.items
    }
}

impl<L: ListLen, T: TlsCodable> From<Vec<T>> for TlsList<L, T> {
    fn from(items: Vec<T>) -> Self {
        Self {
            items,
            _l: PhantomData,
        }
    }
}

pub type U16PrefixedVec<T> = TlsList<u16, T>;
pub type U8PrefixedVec<T> = TlsList<u8, T>;

pub fn main() {
    let data = vec![0, 0, 4, 0, 2, 8, 8];
    let mut reader = Reader::new(&data);
    let x = TlsList::<u24, u16>::read_from(&mut reader);
    println!("{:?}", x);

    let list: TlsList<u24, u16> = vec![77, 88].into();
    let x = list.get_encoding();
    println!("{:?}", x);
    println!(
        "{:?}",
        TlsList::<u24, u16>::read_from(&mut Reader::new(&x))
            .unwrap()
            .get_encoding()
    );
}
