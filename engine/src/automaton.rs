//! Sequencer's Automaton: automatic statistical analysis of a set of samples.
//!
//! Burp's Automaton view runs the same statistical tests as the manual Sequencer across a whole set
//! of requests, and additionally detects the character set those samples are drawn from.

use std::collections::BTreeMap;

/// One statistical test's verdict over a set of samples.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub test: &'static str,
    /// Burp labels each test Pass, Interest or Fail.
    pub outcome: Outcome,
    pub observed: f64,
    pub p_value: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No bias detected; the sample looks random.
    Pass,
    /// Deviation worth a look.
    Interest,
    /// Strong bias; almost certainly not random.
    Fail,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Pass => "Pass",
            Outcome::Interest => "Interest",
            Outcome::Fail => "Fail",
        }
    }
}

/// Shannon entropy in bits per byte, 0.0 to 8.0.
pub fn entropy(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in sample {
        counts[*byte as usize] += 1;
    }
    let total = sample.len() as f64;
    let mut bits = 0.0;
    for count in counts.iter() {
        if *count == 0 {
            continue;
        }
        let p = *count as f64 / total;
        bits -= p * p.log2();
    }
    bits
}

/// How uneven the byte values are, 0.0 to 1.0. **Zero means perfectly uniform**; higher means more
/// structure.
///
/// This is the chi-square statistic against a uniform expectation, normalised so a fully uniform
/// sample gives 0 and a single-value sample gives close to 1. An earlier version called this a
/// "good distribution" score, which inverted the meaning of every threshold that used it.
pub fn skew(sample: &[u8]) -> f64 {
    if sample.len() < 2 {
        return 0.0;
    }
    let expected = sample.len() as f64 / 256.0;
    let mut counts = [0usize; 256];
    for byte in sample {
        counts[*byte as usize] += 1;
    }
    let chi: f64 = counts
        .iter()
        .map(|c| {
            let d = *c as f64 - expected;
            d * d / expected
        })
        .sum();
    // The worst case is every byte in one bucket, which gives chi = 255n. Normalising by that
    // makes a single-value sample score 1.0 and a perfectly uniform one 0.0.
    let max = sample.len() as f64 * 255.0;
    (chi / max).clamp(0.0, 1.0)
}

/// Fraction of bit positions where every sample carries the same value. **1.0 means every bit is
/// constant across the set**, which is maximum bias; 0.0 means every bit varies.
///
/// This is the bit-by-bit test. It was previously named `bit_uniformity`, which read as the opposite
/// of what it measures: identical samples scored 1.0 and looked "uniform" rather than maximally
/// biased.
pub fn bit_agreement(samples: &[Vec<u8>]) -> f64 {
    let Some(width) = samples.iter().map(Vec::len).min() else {
        return 0.0;
    };
    if width == 0 || samples.len() < 2 {
        return 0.0;
    }
    let mut uniform = 0usize;
    let mut total = 0usize;
    for byte_index in 0..width {
        for bit in 0..8 {
            let ones = samples
                .iter()
                .filter(|sample| sample[byte_index] >> bit & 1 == 1)
                .count();
            if ones == 0 || ones == samples.len() {
                uniform += 1;
            }
            total += 1;
        }
    }
    uniform as f64 / total as f64
}

/// Runs the standard suite across every sample.
pub fn analyse(samples: &[Vec<u8>]) -> Vec<Verdict> {
    if samples.is_empty() {
        return Vec::new();
    }
    let joined: Vec<u8> = samples.iter().flat_map(|s| s.iter().copied()).collect();
    let mean_bits = samples.iter().map(|s| entropy(s)).sum::<f64>() / samples.len() as f64;

    let mut verdicts = Vec::new();

    // Entropy: too little structure to be random. The threshold is relative to what the sample can
    // possibly show. Observing 16 samples over 16 positions cannot exceed log2(16) = 4 bits per
    // position however random they are, so a fixed 5-bit "Pass" bar would fail genuinely random data.
    let width = samples.iter().map(Vec::len).min().unwrap_or(0);
    let achievable = if samples.len().min(width) > 1 {
        (samples.len().min(width) as f64).log2()
    } else {
        8.0
    };
    let bits_outcome = match mean_bits / achievable {
        r if r < 0.75 => Outcome::Fail,
        r if r < 0.9 => Outcome::Interest,
        _ => Outcome::Pass,
    };
    verdicts.push(Verdict {
        test: "Entropy",
        outcome: bits_outcome,
        observed: mean_bits,
        p_value: mean_bits / 8.0,
    });

    // Byte skew: one value dominating means structure.
    let skew_value = skew(&joined);
    let spread_outcome = match skew_value {
        s if s < 0.05 => Outcome::Pass,
        s if s < 0.15 => Outcome::Interest,
        _ => Outcome::Fail,
    };
    verdicts.push(Verdict {
        test: "Byte skew",
        outcome: spread_outcome,
        observed: skew_value,
        p_value: 1.0 - skew_value,
    });

    // Bit-by-bit: agreement across samples. High agreement means little variation.
    let agreement = bit_agreement(samples);
    let bit_outcome = match agreement {
        a if a < 0.5 => Outcome::Pass,
        a if a < 0.9 => Outcome::Interest,
        _ => Outcome::Fail,
    };
    verdicts.push(Verdict {
        test: "Bit agreement",
        outcome: bit_outcome,
        observed: agreement,
        p_value: 1.0 - agreement,
    });

    // Length: identical lengths across every sample is a strong signal.
    let lengths: Vec<usize> = samples.iter().map(Vec::len).collect();
    let same = lengths.windows(2).all(|w| w[0] == w[1]);
    verdicts.push(Verdict {
        test: "Length",
        outcome: if same && lengths.len() > 1 {
            Outcome::Interest
        } else {
            Outcome::Pass
        },
        observed: lengths.iter().min().copied().unwrap_or(0) as f64,
        p_value: 1.0,
    });

    verdicts
}

/// The character set the samples are drawn from, as a readable string.
///
/// Burp reports a detected set such as "Hexadecimal" or "Base64"; this returns the printable
/// characters actually observed, plus a guess at the encoding family.
pub fn detect_charset(samples: &[Vec<u8>]) -> (String, &'static str) {
    let joined: Vec<u8> = samples.iter().flat_map(|s| s.iter().copied()).collect();
    if joined.is_empty() {
        return (String::new(), "unknown");
    }
    let mut printable = String::new();
    for byte in &joined {
        let ch = *byte as char;
        if ch.is_ascii_graphic() || ch == ' ' {
            printable.push(ch);
        }
    }
    // Order matters: every decimal digit is also a hexadecimal digit, so a digit-only sample must
    // be checked first or numeric data is reported as hexadecimal.
    let family = if joined.iter().all(|b| b.is_ascii_digit()) {
        "Decimal"
    } else if joined
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
    {
        if joined.iter().all(|b| b.is_ascii_hexdigit()) {
            "Hexadecimal"
        } else {
            "Base64"
        }
    } else if joined.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        "ASCII"
    } else {
        "Binary"
    };
    (printable, family)
}

/// Groups samples by length, which is how the Automaton shows comparable sample sets.
pub fn by_length(samples: &[Vec<u8>]) -> BTreeMap<usize, usize> {
    let mut out = BTreeMap::new();
    for sample in samples {
        *out.entry(sample.len()).or_default() += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_samples() -> Vec<Vec<u8>> {
        (0..16)
            .map(|i| format!("{i:016x}").into_bytes())
            .collect()
    }

    #[test]
    fn entropy_of_random_bytes_is_high() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert!(entropy(&bytes) > 7.9, "got {}", entropy(&bytes));
    }

    #[test]
    fn entropy_of_a_constant_is_zero() {
        assert!(entropy(&[7u8; 64]) < 0.001);
    }

    #[test]
    fn entropy_of_nothing_does_not_divide_by_zero() {
        assert_eq!(entropy(&[]), 0.0);
    }

    #[test]
    fn a_constant_sample_is_maximally_skewed() {
        assert!(skew(&[0u8; 32]) > 0.9, "got {}", skew(&[0u8; 32]));
    }

    #[test]
    fn uniform_bytes_have_no_skew() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert!(skew(&bytes) < 0.01, "got {}", skew(&bytes));
    }

    #[test]
    fn identical_samples_agree_on_every_bit() {
        // Every sample identical means every bit is constant: maximum agreement, maximum bias.
        let fixed = vec![vec![0b1010_1010u8; 4]; 8];
        assert!(bit_agreement(&fixed) > 0.99, "got {}", bit_agreement(&fixed));
    }

    #[test]
    fn varying_samples_agree_on_few_bits() {
        let mut state: u32 = 99;
        let varying: Vec<Vec<u8>> = (0..64)
            .map(|_| {
                let mut bytes = Vec::with_capacity(4);
                for _ in 0..4 {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    bytes.push((state >> 16) as u8);
                }
                bytes
            })
            .collect();
        assert!(bit_agreement(&varying) < 0.2, "got {}", bit_agreement(&varying));
    }

    #[test]
    fn a_single_sample_cannot_be_compared() {
        assert_eq!(bit_agreement(&[vec![1, 2, 3]]), 0.0);
    }

    #[test]
    fn varied_samples_pass_the_suite() {
        // A row of pseudo-random bytes. Hex-padded counters would not qualify: their leading zeros
        // really are low entropy, and the analyser is right to say so.
        let mut state: u32 = 0x1234_5678;
        let samples: Vec<Vec<u8>> = (0..16)
            .map(|_| {
                let mut bytes = Vec::with_capacity(16);
                for _ in 0..16 {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    bytes.push((state >> 16) as u8);
                }
                bytes
            })
            .collect();
        let verdicts = analyse(&samples);
        assert_eq!(verdicts.len(), 4);
        assert_eq!(verdicts[0].test, "Entropy");
        assert_eq!(verdicts[0].outcome, Outcome::Pass, "entropy {:?}", verdicts[0]);
        assert_eq!(verdicts[2].outcome, Outcome::Pass, "bits {:?}", verdicts[2]);
    }

    #[test]
    fn zero_padded_samples_really_are_low_entropy() {
        // Guards the assumption in the test above: padded hex is biased, and must be reported so.
        let verdicts = analyse(&hex_samples());
        assert_eq!(verdicts[0].outcome, Outcome::Fail);
    }

    #[test]
    fn identical_constant_samples_are_reported_as_biased() {
        let samples = vec![vec![0u8; 8]; 10];
        let verdicts = analyse(&samples);
        assert_eq!(verdicts[0].outcome, Outcome::Fail, "entropy should fail");
        assert_eq!(verdicts[1].outcome, Outcome::Fail, "byte skew should fail");
        assert_eq!(verdicts[2].outcome, Outcome::Fail, "bit agreement should fail");
        assert_eq!(verdicts[3].outcome, Outcome::Interest, "equal lengths are notable");
    }

    #[test]
    fn no_samples_produce_no_verdicts() {
        assert!(analyse(&[]).is_empty());
    }

    #[test]
    fn character_sets_are_detected() {
        assert_eq!(detect_charset(&hex_samples()).1, "Hexadecimal");
        let b64: Vec<Vec<u8>> = vec![b"YWJjZA==".to_vec(), b"ZWZnaGk=".to_vec()];
        assert_eq!(detect_charset(&b64).1, "Base64");
        let numeric: Vec<Vec<u8>> = vec![b"12345".to_vec(), b"67890".to_vec()];
        assert_eq!(detect_charset(&numeric).1, "Decimal");
        assert_eq!(detect_charset(&[]).1, "unknown");
    }

    #[test]
    fn samples_group_by_length() {
        // Two samples of length 2, one each of length 1 and 3.
        let groups = by_length(&[vec![1, 2], vec![3], vec![4, 5, 6], vec![7, 8]]);
        assert_eq!(groups.get(&2), Some(&2));
        assert_eq!(groups.get(&1), Some(&1));
        assert_eq!(groups.get(&3), Some(&1));
        assert_eq!(groups.len(), 3);
    }
}
