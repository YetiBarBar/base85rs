//! A library to encode and decode Base85 [RFC1924 variant](https://datatracker.ietf.org/doc/html/rfc1924)
//!
//! This is only one variant of Base85, not the most common one (ASCII-85 and Z85 are wider spread). This
//! variant will most likely been seen in CTF challenges.
//!
//! During decoding, whitespaces are ignored.

#[inline]
fn to_x85(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b'a'..=b'z' => Some(c - b'a' + 36),
        b'!' => Some(62),
        b'#' => Some(63),
        b'$' => Some(64),
        b'%' => Some(65),
        b'&' => Some(66),
        b'(' => Some(67),
        b')' => Some(68),
        b'*' => Some(69),
        b'+' => Some(70),
        b'-' => Some(71),
        b';' => Some(72),
        b'<' => Some(73),
        b'=' => Some(74),
        b'>' => Some(75),
        b'?' => Some(76),
        b'@' => Some(77),
        b'^' => Some(78),
        b'_' => Some(79),
        b'`' => Some(80),
        b'{' => Some(81),
        b'|' => Some(82),
        b'}' => Some(83),
        b'~' => Some(84),
        _ => None,
    }
}

static BASE85_CHARS: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

#[must_use]
// Encode a single chunk. At most 4 bytes, at least 1.
fn encode_u32_chunk(chunk: &[u8], buffer: &mut [u8; 5]) -> usize {
    let in_value = u32::from_be_bytes(match chunk.len() {
        1 => [chunk[0], 0, 0, 0],
        2 => [chunk[0], chunk[1], 0, 0],
        3 => [chunk[0], chunk[1], chunk[2], 0],
        4 => [chunk[0], chunk[1], chunk[2], chunk[3]],
        _ => unreachable!(),
    });

    let in_value = usize::try_from(in_value).unwrap();

    // Powers of 85: 85, 7_225, 614_125,52_200_625
    *buffer = [
        BASE85_CHARS[in_value / 52_200_625],
        BASE85_CHARS[(in_value % 52_200_625) / 614_125],
        BASE85_CHARS[(in_value % 614_125) / 7_225],
        BASE85_CHARS[(in_value % 7_225_usize) / 85],
        BASE85_CHARS[in_value % 85_usize],
    ];
    chunk.len()
}

/// encode() turns a slice of bytes into base85 encoded `String`
///
/// # Example
///
/// ```
/// let data = [b'a'];
/// let encoded = base85rs::encode(&data);
/// assert_eq!(encoded, "VE");
/// ```
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut buffer = [0; 5];

    let outdata = data
        .chunks(4)
        .fold(Vec::with_capacity(data.len()), |mut acc, chunk| {
            let c = encode_u32_chunk(chunk, &mut buffer);
            acc.extend(buffer[0..=c].iter());
            acc
        });
    String::from_utf8(outdata).unwrap_or_default()
}

// Decode a single chunk. At most, 5 `u8`, at least one.
fn decode_chunk(chunk: &[u8]) -> Option<[u8; 4]> {
    chunk
        .iter()
        .try_fold(0, |mut acc, item| match to_x85(*item) {
            Some(value) => {
                acc *= 85;
                acc += u32::from(value);
                Some(acc)
            }
            _ => None,
        })
        .map(u32::to_be_bytes)
}

/// decode() try to decode a base85 encoded &str and return an `Option<Vec<u8>>`
///
/// # Example
///
/// ```
/// let data = "VE";
/// let decoded = base85rs::decode(&data);
/// assert_eq!(decoded, Some(vec![b'a']));
/// ```
#[must_use]
pub fn decode(instr: &str) -> Option<Vec<u8>> {
    let data: Vec<u8> = instr
        .as_bytes()
        .iter()
        .filter(|&chr| *chr != 0x20)
        .copied()
        .collect();

    let mut outdata = Vec::<u8>::new();

    for chunk in data.chunks_exact(5) {
        let value = decode_chunk(chunk)?;
        outdata.extend(value);
    }

    let rem = data.len() % 5;
    if rem != 0 {
        let in_index = &data[data.len() - rem..];
        let chunk_len = in_index.len();
        let mut in_index = in_index.to_vec();

        while in_index.len() != 5 {
            in_index.push(126);
        }

        let accumulator = decode_chunk(&in_index)?;
        outdata.extend(&accumulator[0..chunk_len - 1]);
    }

    Some(outdata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty_list() {
        assert_eq!(encode("".as_bytes()), "");
    }

    #[test]
    fn encode_one_char() {
        assert_eq!(encode("a".as_bytes()), "VE");
    }

    #[test]
    fn encode_two_char() {
        assert_eq!(encode("aa".as_bytes()), "VPO");
    }
    #[test]
    fn encode_three_char() {
        assert_eq!(encode("aaa".as_bytes()), "VPRn");
    }
    #[test]
    fn encode_four_char() {
        assert_eq!(encode("aaaa".as_bytes()), "VPRom");
    }
    #[test]
    fn encode_five_char() {
        assert_eq!(encode("aaaaa".as_bytes()), "VPRomVE");
    }
    #[test]
    fn encode_six_char() {
        assert_eq!(encode("aaaaaa".as_bytes()), "VPRomVPO");
    }
    #[test]
    fn encode_seven_char() {
        assert_eq!(encode("aaaaaaa".as_bytes()), "VPRomVPRn");
    }
    #[test]
    fn encode_word_set() {
        let wordlist = [
            ("relimitation", "a%F63ZE192bZKvH"),
            ("pollenless", "aBpmEWo~R`b8`"),
            ("countercompetition", "V{dhCbY*g5Z*6d8bZK;HZ*B"),
            ("toothbrushing", "bZ>8TXkv18b7*O9X8"),
            ("cavekeeper", "V_|k>Yh`6{WpV"),
            ("microsomial", "ZE0h2Z*y;LX<=*"),
        ];
        for (word, res) in wordlist {
            assert_eq!(encode(word.as_bytes()), res);
        }
    }
    #[test]
    fn decode_empty_list() {
        assert_eq!(decode("").unwrap(), "".as_bytes());
    }

    #[test]
    fn decode_one_char() {
        assert_eq!(decode("VE").unwrap(), "a".as_bytes());
    }

    #[test]
    fn decode_two_char() {
        assert_eq!(decode("VPO").unwrap(), "aa".as_bytes());
    }
    #[test]
    fn decode_three_char() {
        assert_eq!(decode("VPRn").unwrap(), "aaa".as_bytes());
    }
    #[test]
    fn decode_four_char() {
        assert_eq!(decode("VPRom").unwrap(), "aaaa".as_bytes());
    }
    #[test]
    fn decode_five_char() {
        assert_eq!(decode("VPRomVE").unwrap(), "aaaaa".as_bytes());
    }
    #[test]
    fn decode_six_char() {
        assert_eq!(decode("VPRomVPO").unwrap(), "aaaaaa".as_bytes());
    }
    #[test]
    fn decode_seven_char() {
        assert_eq!(decode("VPRomVPRn").unwrap(), "aaaaaaa".as_bytes());
    }
    #[test]
    fn decode_word_set() {
        let wordlist = [
            ("relimitation", "a%F63ZE192bZKvH"),
            ("pollenless", "aBpmEWo~R`b8`"),
            ("countercompetition", "V{dhCbY*g5Z*6d8bZK;HZ*B"),
            ("toothbrushing", "bZ>8TXkv18b7*O9X8"),
            ("cavekeeper", "V_|k>Yh`6{WpV"),
            ("microsomial", "ZE0h2Z*y;LX<=*"),
        ];
        for (word, res) in wordlist {
            assert_eq!(decode(res).unwrap(), word.as_bytes());
        }
    }

    #[test]
    fn decode_with_whitespace() {
        let wordlist = [
            ("relimitation", "a%F63ZE1 92bZKvH"),
            ("pollenless", "aBp mEWo~ R`b8`"),
            ("countercompetition", "V{dhCbY *g5Z*6d8bZK ;HZ*B"),
            ("toothbrushing", "bZ>8 TXkv18b7* O9X8"),
            ("cavekeeper", "V_| k>Yh`6{ WpV"),
            ("microsomial", "ZE0h2Z*y ;LX<=*"),
        ];
        for (word, res) in wordlist {
            assert_eq!(decode(res).unwrap(), word.as_bytes());
        }
    }

    #[test]
    fn decode_invalid() {
        assert!(decode("]").is_none())
    }
}
