use crate::utils::errors::MessageError;
use std::io::Read;

const MAX_U8: usize = 252;
const MAX_U16: usize = 65535;
const MAX_U32: usize = 4294967295;

/// Convierte un numero usize a un numero que respete el formato
/// CompactSize, agregando los prefijos necesarios en base al tamano
/// del numero en cuestion.
pub fn make_compact(number: usize) -> Vec<u8> {
    let mut number_as_cmp: Vec<u8> = Vec::new();
    if number <= MAX_U8 {
        let bytes = number.to_le_bytes();
        number_as_cmp.extend_from_slice(&bytes[..1]);
    } else if number <= MAX_U16 {
        let start = [0xfd];
        let bytes = number.to_le_bytes();
        let first_two_bytes = &bytes[..2];
        number_as_cmp.extend(&start);
        number_as_cmp.extend(first_two_bytes);
    } else if number <= MAX_U32 {
        let start = [0xfe];
        let bytes = number.to_le_bytes();
        let first_four_bytes = &bytes[..4];
        number_as_cmp.extend_from_slice(&start);
        number_as_cmp.extend_from_slice(first_four_bytes);
    } else {
        let start = [0xff];
        number_as_cmp.extend_from_slice(&start);
        number_as_cmp.extend_from_slice(&number.to_le_bytes());
    }

    number_as_cmp
}

fn parse_after_first_byte(
    stream: &mut dyn Read,
    first_byte: [u8; 1],
) -> Result<usize, MessageError> {
    match first_byte[0] {
        0xfd => {
            let mut extra = [0; 2];
            stream.read_exact(&mut extra)?;
            Ok(u16::from_le_bytes(extra) as usize)
        }
        0xfe => {
            let mut extra = [0; 4];
            stream.read_exact(&mut extra)?;
            Ok(u32::from_le_bytes(extra) as usize)
        }
        0xff => {
            let mut extra = [0; 8];
            stream.read_exact(&mut extra)?;
            Ok(u64::from_le_bytes(extra) as usize)
        }
        _ => Ok(first_byte[0] as usize),
    }
}

/// Lee de un stream el primer byte y decide si se trata de un Witness Flag + `CompactSize`,
/// o unicamente un compact size.
/// # Errors
/// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
/// es un `MessageError::IncompleteMessage`
pub fn parse_compact_and_witness(stream: &mut dyn Read) -> Result<(bool, usize), MessageError> {
    let mut buf_flag: [u8; 1] = [0; 1];
    stream.read_exact(&mut buf_flag)?;
    if buf_flag[0] == 0x00 {
        stream.read_exact(&mut buf_flag)?;
        let tx_in_count = parse_compact(stream)?;
        Ok((true, tx_in_count))
    } else {
        let tx_in_count = parse_after_first_byte(stream, buf_flag)?;
        Ok((false, tx_in_count))
    }
}

/// Parsea un `CompactSize`, pasandolo a usize.
/// # Errors
/// * al intentar leer del stream, no se encuentra la cantidad de bytes pedida. El error obtenido
/// es un `MessageError::IncompleteMessage`
pub fn parse_compact(stream: &mut dyn Read) -> Result<usize, MessageError> {
    let mut buf = [0; 1];
    stream.read_exact(&mut buf)?;
    parse_after_first_byte(stream, buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    #[test]
    fn parse_compact_does_parsing_appropriately_for_u8() -> Result<(), MessageError> {
        let mut content = Vec::new();
        let num: u8 = 238;
        content.extend_from_slice(&num.to_le_bytes());
        let mut reader = BufReader::new(content.as_slice());
        let parsed = parse_compact(&mut reader)?;
        assert_eq!(num as usize, parsed);
        Ok(())
    }
    #[test]
    fn parse_compact_does_parsing_appropriately_for_u16() -> Result<(), MessageError> {
        let mut content: Vec<u8> = Vec::new();
        let num: u16 = 5000;
        let start = [0xfd];
        content.extend_from_slice(&start);
        content.extend_from_slice(&num.to_le_bytes());
        let mut reader = BufReader::new(content.as_slice());
        let parsed = parse_compact(&mut reader)?;
        assert_eq!(num as usize, parsed);
        Ok(())
    }
    #[test]
    fn parse_compact_does_parsing_appropriately_for_u32() -> Result<(), MessageError> {
        let mut content: Vec<u8> = Vec::new();
        let num: u32 = 70000;
        let start = [0xfe];
        content.extend_from_slice(&start);
        content.extend_from_slice(&num.to_le_bytes());
        let mut reader = BufReader::new(content.as_slice());
        let parsed = parse_compact(&mut reader)?;
        assert_eq!(num as usize, parsed);
        Ok(())
    }
    #[test]
    fn parse_compact_does_parsing_appropriately_for_u64() -> Result<(), MessageError> {
        let mut content: Vec<u8> = Vec::new();
        let num: u64 = 4294967300;
        let start = [0xff];
        content.extend_from_slice(&start);
        content.extend_from_slice(&num.to_le_bytes());
        let mut reader = BufReader::new(content.as_slice());
        let parsed = parse_compact(&mut reader)?;
        assert_eq!(num as usize, parsed);
        Ok(())
    }
    #[test]
    fn make_compact_can_make_compact_from_u8() {
        let number = 200;
        assert_eq!(make_compact(number), [0xc8]);
    }

    #[test]
    fn make_compact_can_make_compact_from_u16() {
        let number = MAX_U8 + 3;
        let result: [u8; 3] = [0xfd, 0xff, 0x00];
        assert_eq!(make_compact(number), result);
    }
    #[test]
    fn make_compact_can_make_compact_from_u32() {
        let number = MAX_U16 + 10;
        let result: [u8; 5] = [0xfe, 0x09, 0x00, 0x01, 0x00];
        assert_eq!(make_compact(number), result);
    }

    #[test]
    fn make_compact_can_make_compact_from_u64() {
        let number = MAX_U32 + 10;
        let result: [u8; 9] = [0xff, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(make_compact(number), result);
    }
}
