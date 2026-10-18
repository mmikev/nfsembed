use std::fmt;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum DecodeError {
    #[error("truncated XDR value")]
    Truncated,
    #[error("invalid XDR boolean {0}")]
    InvalidBoolean(u32),
    #[error("invalid {kind} discriminant {value}")]
    InvalidDiscriminant { kind: &'static str, value: u32 },
    #[error("{field} length {actual} exceeds limit {limit}")]
    LimitExceeded {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("invalid non-zero XDR padding")]
    InvalidPadding,
    #[error("trailing bytes after XDR value")]
    TrailingBytes,
    #[error("XDR length arithmetic overflow")]
    Overflow,
}

pub struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.position.checked_add(count).ok_or(DecodeError::Overflow)?;
        let value = self.input.get(self.position..end).ok_or(DecodeError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| DecodeError::Truncated)?))
    }

    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().map_err(|_| DecodeError::Truncated)?))
    }

    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| DecodeError::Truncated)?))
    }

    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        match self.read_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(DecodeError::InvalidBoolean(value)),
        }
    }

    pub fn read_enum<T>(
        &mut self,
        kind: &'static str,
        convert: impl FnOnce(u32) -> Option<T>,
    ) -> Result<T, DecodeError> {
        let value = self.read_u32()?;
        convert(value).ok_or(DecodeError::InvalidDiscriminant { kind, value })
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Truncated)
    }

    pub fn read_opaque(&mut self, field: &'static str, limit: usize) -> Result<Vec<u8>, DecodeError> {
        Ok(self.read_opaque_slice(field, limit)?.to_vec())
    }

    /// Reads a variable-length opaque value without copying it out of the
    /// decoder input. Callers that only inspect a value should prefer this to
    /// `read_opaque`.
    pub fn read_opaque_slice(&mut self, field: &'static str, limit: usize) -> Result<&'a [u8], DecodeError> {
        let length = self.read_length(field, limit)?;
        let value = self.take(length)?;
        let padding = (4usize.wrapping_sub(length & 3)) & 3;
        if self.take(padding)?.iter().any(|byte| *byte != 0) {
            return Err(DecodeError::InvalidPadding);
        }
        Ok(value)
    }

    pub fn read_string(&mut self, field: &'static str, limit: usize) -> Result<Vec<u8>, DecodeError> {
        self.read_opaque(field, limit)
    }

    pub fn read_array<T>(
        &mut self,
        field: &'static str,
        limit: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let length = self.read_length(field, limit)?;
        let mut result = Vec::new();
        result.try_reserve_exact(length).map_err(|_| DecodeError::LimitExceeded {
            field,
            actual: length,
            limit,
        })?;
        for _ in 0..length {
            result.push(decode(self)?);
        }
        Ok(result)
    }

    fn read_length(&mut self, field: &'static str, limit: usize) -> Result<usize, DecodeError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| DecodeError::Overflow)?;
        if length > limit {
            return Err(DecodeError::LimitExceeded {
                field,
                actual: length,
                limit,
            });
        }
        Ok(length)
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[derive(Default)]
pub struct Encoder {
    output: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an encoder with room for a known fixed protocol prefix or
    /// bounded reply, avoiding geometric growth for predictable messages.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
        }
    }

    pub fn write_u32(&mut self, value: u32) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn len(&self) -> usize {
        self.output.len()
    }

    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    /// Discards everything written after the first `length` bytes.
    pub fn truncate(&mut self, length: usize) {
        self.output.truncate(length);
    }

    pub fn write_u64(&mut self, value: u64) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_u32(u32::from(value));
    }

    pub fn write_fixed(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
    }

    pub fn write_opaque(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        let length = u32::try_from(value.len()).map_err(|_| EncodeError::TooLarge(value.len()))?;
        let padding = (4 - value.len() % 4) % 4;
        let final_length = self
            .output
            .len()
            .checked_add(4)
            .and_then(|length| length.checked_add(value.len()))
            .and_then(|length| length.checked_add(padding))
            .ok_or(EncodeError::TooLarge(value.len()))?;
        self.write_u32(length);
        self.output.extend_from_slice(value);
        self.output.resize(final_length, 0);
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("value of {0} bytes cannot be represented in XDR")]
    TooLarge(usize),
    #[error("NFS time {seconds}.{nanoseconds:09} cannot be represented on the wire")]
    InvalidTime { seconds: u64, nanoseconds: u32 },
}

impl fmt::Debug for Decoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("position", &self.position)
            .field("remaining", &self.remaining())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_boolean() {
        let input = 2u32.to_be_bytes();
        let mut decoder = Decoder::new(&input);
        assert_eq!(decoder.read_bool(), Err(DecodeError::InvalidBoolean(2)));
    }

    #[test]
    fn checks_opaque_limit_before_allocating() {
        let input = 1000u32.to_be_bytes();
        let mut decoder = Decoder::new(&input);
        assert!(matches!(decoder.read_opaque("name", 255), Err(DecodeError::LimitExceeded { actual: 1000, .. })));
    }

    #[test]
    fn opaque_round_trip_and_finish() {
        let mut encoder = Encoder::new();
        encoder.write_opaque(b"abc").unwrap();
        let bytes = encoder.into_bytes();
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_opaque("value", 3).unwrap(), b"abc");
        decoder.finish().unwrap();
    }

    #[test]
    fn opaque_padding_must_be_zero_and_is_written_as_zero() {
        let mut encoder = Encoder::new();
        encoder.write_opaque(b"a").unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(bytes, [0, 0, 0, 1, b'a', 0, 0, 0]);

        let mut bad_padding = bytes.clone();
        bad_padding[7] = 1;
        assert_eq!(Decoder::new(&bad_padding).read_opaque("value", 8), Err(DecodeError::InvalidPadding));
        assert_eq!(Decoder::new(&bytes[..6]).read_opaque("value", 8), Err(DecodeError::Truncated));
    }

    #[test]
    fn arrays_enforce_their_limit_and_finish_rejects_trailing_bytes() {
        let mut encoder = Encoder::new();
        encoder.write_u32(2);
        encoder.write_u32(10);
        encoder.write_u32(20);
        encoder.write_u32(99);
        let bytes = encoder.into_bytes();

        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_array("values", 2, Decoder::read_u32).unwrap(), [10, 20]);
        assert_eq!(decoder.remaining(), 4);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));

        assert_eq!(
            Decoder::new(&bytes).read_array("values", 1, Decoder::read_u32),
            Err(DecodeError::LimitExceeded {
                field: "values",
                actual: 2,
                limit: 1,
            })
        );
    }

    #[test]
    fn fixed_width_values_round_trip_and_reject_truncation() {
        let mut encoder = Encoder::with_capacity(32);
        encoder.write_u64(u64::MAX - 1);
        encoder.write_bool(true);
        encoder.write_fixed(&[1, 2, 3, 4]);
        encoder.write_u32(i32::MIN as u32);
        assert_eq!(encoder.len(), 20);
        let bytes = encoder.into_bytes();

        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_u64(), Ok(u64::MAX - 1));
        assert_eq!(decoder.read_bool(), Ok(true));
        assert_eq!(decoder.read_fixed::<4>(), Ok([1, 2, 3, 4]));
        assert_eq!(decoder.read_i32(), Ok(i32::MIN));
        assert_eq!(decoder.position(), 20);
        assert_eq!(decoder.read_u32(), Err(DecodeError::Truncated));
        decoder.finish().unwrap();
        assert_eq!(
            Decoder::new(&[0; 3]).read_enum("kind", |value| (value == 0).then_some(())),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            Decoder::new(&[0, 0, 0, 7]).read_enum("kind", |value| (value == 0).then_some(())),
            Err(DecodeError::InvalidDiscriminant { kind: "kind", value: 7 })
        );
    }

    #[test]
    fn truncated_opaque_corpus_never_succeeds_or_panics() {
        for declared in 0u32..64 {
            for available in 0usize..64 {
                let mut input = declared.to_be_bytes().to_vec();
                input.resize(4 + available, 0xaa);
                let mut decoder = Decoder::new(&input);
                let result = decoder.read_opaque("fuzz opaque", 32);
                if declared > 32 || available < declared as usize + ((4 - declared as usize % 4) % 4) {
                    assert!(result.is_err());
                }
            }
        }
    }
}
