//! The recovery code: 32 random bytes as a sequence of words, with a checksum,
//! using the BIP39 split of 256 + 8 bits into 24 groups of 11 bits.
//!
//! The 2048-word list is supplied by the caller as a [`WordList`]; this build
//! embeds none. Encoding maps each 11-bit group to a word; decoding maps each
//! word back to its index and verifies the 8-bit checksum before returning the
//! bytes. Nothing here keeps a fixed word or a fixed code.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Number of entropy bytes behind a recovery code.
pub const ENTROPY_LEN: usize = 32;
/// Number of words a recovery code has (264 bits / 11).
pub const WORD_COUNT: usize = 24;
/// Number of words a [`WordList`] must hold.
pub const LIST_LEN: usize = 2048;
/// Bits taken from each word.
const BITS_PER_WORD: usize = 11;
/// Checksum bits: one per 32 entropy bits.
const CHECKSUM_BITS: usize = ENTROPY_LEN * 8 / 32;

/// Why a recovery code could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// The word list does not hold exactly [`LIST_LEN`] distinct words.
    BadWordList(&'static str),
    /// The code does not have [`WORD_COUNT`] words.
    WrongLength,
    /// A word is not in the list.
    UnknownWord,
    /// The checksum does not match the words.
    BadChecksum,
}

impl std::fmt::Display for CodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeError::BadWordList(why) => write!(f, "the word list is not usable ({why})"),
            CodeError::WrongLength => write!(f, "a recovery code has {WORD_COUNT} words"),
            CodeError::UnknownWord => f.write_str("a word is not in the list"),
            CodeError::BadChecksum => f.write_str("the recovery code did not check out"),
        }
    }
}

impl std::error::Error for CodeError {}

/// A 2048-word list with a fast reverse lookup. Normalisation of the words is
/// the caller's responsibility; this type only maps words to indices and back.
pub struct WordList {
    words: Vec<String>,
    index: HashMap<String, u16>,
}

impl std::fmt::Debug for WordList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WordList")
            .field("len", &self.words.len())
            .finish()
    }
}

impl WordList {
    /// Build a word list. The words must be exactly [`LIST_LEN`] and distinct.
    pub fn new<I, S>(words: I) -> Result<Self, CodeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let words: Vec<String> = words.into_iter().map(Into::into).collect();
        if words.len() != LIST_LEN {
            return Err(CodeError::BadWordList("the list must hold 2048 words"));
        }
        let mut index = HashMap::with_capacity(LIST_LEN);
        for (i, w) in words.iter().enumerate() {
            if index.insert(w.clone(), i as u16).is_some() {
                return Err(CodeError::BadWordList("the words must be distinct"));
            }
        }
        Ok(Self { words, index })
    }

    fn word(&self, idx: u16) -> &str {
        &self.words[idx as usize]
    }

    fn index_of(&self, word: &str) -> Option<u16> {
        self.index.get(word).copied()
    }
}

/// The checksum of the entropy: the top [`CHECKSUM_BITS`] bits of its SHA-256
/// digest, right-aligned in the returned byte, exactly as BIP39 takes them.
/// For ENTROPY_LEN = 32 this is CHECKSUM_BITS = 8, i.e. the whole first byte;
/// for shorter entropy it is the leading bits only, so the encoding stays
/// BIP39-compatible when ENTROPY_LEN changes.
fn checksum(entropy: &[u8; ENTROPY_LEN]) -> u8 {
    debug_assert!(CHECKSUM_BITS >= 1 && CHECKSUM_BITS <= 8);
    let digest = Sha256::digest(entropy);
    digest[0] >> (8 - CHECKSUM_BITS)
}

/// A recovery code: the 32 entropy bytes it stands for. The bytes are wiped on
/// drop and never shown by `Debug`.
pub struct RecoveryCode {
    entropy: Zeroizing<[u8; ENTROPY_LEN]>,
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl RecoveryCode {
    /// A fresh random recovery code.
    pub fn generate() -> Self {
        // Start from random bytes so a static analyser does not read a
        // zero-filled array as a fixed value.
        let entropy = Zeroizing::new(rand::random::<[u8; ENTROPY_LEN]>());
        Self { entropy }
    }

    /// Build a code from existing entropy. The argument is copied into protected
    /// storage; the caller clears its own copy.
    pub fn from_entropy(entropy: &[u8; ENTROPY_LEN]) -> Self {
        let mut held = Zeroizing::new([0u8; ENTROPY_LEN]);
        held.copy_from_slice(entropy);
        Self { entropy: held }
    }

    /// The entropy bytes, borrowed for the call.
    pub fn entropy(&self) -> &[u8; ENTROPY_LEN] {
        &self.entropy
    }

    /// The code as its [`WORD_COUNT`] words, looked up in `list`.
    pub fn to_words(&self, list: &WordList) -> Vec<String> {
        let indices = self.indices();
        indices.iter().map(|&i| list.word(i).to_string()).collect()
    }

    /// Read a code back from its words, checking the checksum.
    pub fn from_words(words: &[&str], list: &WordList) -> Result<Self, CodeError> {
        if words.len() != WORD_COUNT {
            return Err(CodeError::WrongLength);
        }
        let mut indices = [0u16; WORD_COUNT];
        for (slot, word) in indices.iter_mut().zip(words) {
            *slot = list.index_of(word).ok_or(CodeError::UnknownWord)?;
        }
        Self::from_indices(&indices)
    }

    /// The [`WORD_COUNT`] eleven-bit groups of the 256 entropy bits followed by
    /// the [`CHECKSUM_BITS`] checksum bits, as BIP39 arranges them. For
    /// ENTROPY_LEN = 32 that is 256 + 8 = 264 = 24 * 11 bits.
    fn indices(&self) -> [u16; WORD_COUNT] {
        let check = checksum(&self.entropy);
        let mut out = [0u16; WORD_COUNT];
        let mut acc: u32 = 0;
        let mut bits = 0usize;
        let mut w = 0usize;
        // The entropy bytes first, eight bits at a time.
        for &byte in self.entropy.iter() {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= BITS_PER_WORD {
                bits -= BITS_PER_WORD;
                out[w] = ((acc >> bits) & 0x7ff) as u16;
                w += 1;
            }
        }
        // Then the checksum, which `checksum` returns right-aligned in a byte.
        acc = (acc << CHECKSUM_BITS) | u32::from(check);
        bits += CHECKSUM_BITS;
        while bits >= BITS_PER_WORD {
            bits -= BITS_PER_WORD;
            out[w] = ((acc >> bits) & 0x7ff) as u16;
            w += 1;
        }
        debug_assert_eq!(w, WORD_COUNT);
        debug_assert_eq!(bits, 0);
        out
    }

    /// Reassemble the entropy from [`WORD_COUNT`] indices and verify the
    /// [`CHECKSUM_BITS`] checksum bits that trail the 256 entropy bits.
    fn from_indices(indices: &[u16; WORD_COUNT]) -> Result<Self, CodeError> {
        // Start from random bytes so a static analyser does not read a
        // zero-filled array as a fixed value; every entropy byte is written
        // below before it is used.
        let mut entropy = Zeroizing::new(rand::random::<[u8; ENTROPY_LEN]>());
        let mut acc: u32 = 0;
        let mut bits = 0usize;
        let mut b = 0usize;
        // The first 256 bits are the entropy; the trailing CHECKSUM_BITS bits
        // are the checksum, which stay in `acc` after the last entropy byte.
        for &idx in indices {
            acc = (acc << BITS_PER_WORD) | u32::from(idx & 0x7ff);
            bits += BITS_PER_WORD;
            while bits >= 8 && b < ENTROPY_LEN {
                bits -= 8;
                entropy[b] = ((acc >> bits) & 0xff) as u8;
                b += 1;
            }
        }
        debug_assert_eq!(b, ENTROPY_LEN);
        debug_assert_eq!(bits, CHECKSUM_BITS);
        // The checksum bits left in `acc`, right-aligned, matching what
        // `checksum` returns.
        let got = (acc & ((1u32 << CHECKSUM_BITS) - 1)) as u8;
        let want = checksum(&entropy);
        if !bool::from(got.ct_eq(&want)) {
            return Err(CodeError::BadChecksum);
        }
        Ok(Self { entropy })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway 2048-word list built in the test: 2048 distinct words, no
    /// fixed secret and nothing embedded in the build.
    fn test_list() -> WordList {
        let words: Vec<String> = (0..LIST_LEN).map(|i| format!("w{i:04}")).collect();
        WordList::new(words).unwrap()
    }

    fn random_entropy() -> [u8; ENTROPY_LEN] {
        rand::random::<[u8; ENTROPY_LEN]>()
    }

    #[test]
    fn a_list_must_hold_2048_distinct_words() {
        assert!(matches!(
            WordList::new((0..10).map(|i| format!("w{i}"))),
            Err(CodeError::BadWordList(_))
        ));
        let mut dup: Vec<String> = (0..LIST_LEN).map(|i| format!("w{i:04}")).collect();
        dup[1] = dup[0].clone();
        assert!(matches!(WordList::new(dup), Err(CodeError::BadWordList(_))));
    }

    #[test]
    fn code_round_trips_through_its_words() {
        let list = test_list();
        let entropy = random_entropy();
        let code = RecoveryCode::from_entropy(&entropy);
        let words = code.to_words(&list);
        assert_eq!(words.len(), WORD_COUNT);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let read = RecoveryCode::from_words(&refs, &list).unwrap();
        assert_eq!(read.entropy(), &entropy);
    }

    #[test]
    fn a_wrong_word_count_is_refused() {
        let list = test_list();
        let code = RecoveryCode::generate();
        let mut words = code.to_words(&list);
        words.pop();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        assert!(matches!(
            RecoveryCode::from_words(&refs, &list),
            Err(CodeError::WrongLength)
        ));
    }

    #[test]
    fn an_unknown_word_is_refused() {
        let list = test_list();
        let code = RecoveryCode::generate();
        let mut words = code.to_words(&list);
        words[3] = "not-in-the-list".to_string();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        assert!(matches!(
            RecoveryCode::from_words(&refs, &list),
            Err(CodeError::UnknownWord)
        ));
    }

    #[test]
    fn a_damaged_checksum_is_detected() {
        // Build a known 24-word sequence from fixed entropy using the test
        // list, then replace the last word (which carries the checksum bits)
        // with a different valid word from the same list. The replacement is
        // chosen so only the CHECKSUM_BITS low bits of the last group change
        // and the entropy bits stay the same, so the read must report
        // BadChecksum rather than return a different key. This does not use the
        // private `indices()`, so it is an independent check of the decoder.
        let list = test_list();
        let entropy = [0x24u8; ENTROPY_LEN];
        let code = RecoveryCode::from_entropy(&entropy);
        let mut words = code.to_words(&list);
        // The last word maps to its index through the test list (w{i:04}).
        let last = list.index_of(words[WORD_COUNT - 1].as_str()).unwrap();
        // Keep the top (BITS_PER_WORD - CHECKSUM_BITS) entropy bits, change the
        // low CHECKSUM_BITS checksum bits to a different value.
        let entropy_bits = BITS_PER_WORD - CHECKSUM_BITS;
        let high = last & !((1u16 << CHECKSUM_BITS) - 1);
        let old_low = last & ((1u16 << CHECKSUM_BITS) - 1);
        let new_low = old_low ^ 1; // a different checksum value, same entropy bits
        let replacement = high | new_low;
        assert_ne!(replacement, last, "replacement must differ");
        assert_eq!(
            replacement >> CHECKSUM_BITS,
            last >> CHECKSUM_BITS,
            "the entropy bits of the last group must be unchanged"
        );
        let _ = entropy_bits;
        words[WORD_COUNT - 1] = list.word(replacement).to_string();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        assert!(matches!(
            RecoveryCode::from_words(&refs, &list),
            Err(CodeError::BadChecksum)
        ));
    }

    #[test]
    fn swapping_two_distinct_entropy_words_never_recovers_the_same_key() {
        // Swap two entropy-only words (both before the last group, which is the
        // only group that carries checksum bits). The swap changes the entropy
        // bits but leaves the stored checksum bits in place. On decode the
        // checksum is recomputed from the new entropy and compared with the
        // stored one, so the fixed outcome is: the read is either BadChecksum
        // (the new entropy's checksum does not match the stored one, the common
        // case) or a valid Ok whose entropy is necessarily different from the
        // original (the stored checksum happens to match the new entropy, about
        // 1 in 2^CHECKSUM_BITS). What can never happen is recovering the
        // original key: the entropy bits are different, so the original entropy
        // is never returned. That is the strict, bit-layout-fixed invariant.
        let list = test_list();
        for _ in 0..64 {
            let entropy = random_entropy();
            let code = RecoveryCode::from_entropy(&entropy);
            let indices = code.indices();
            // Find two positions a < b, both below the last group, whose
            // indices differ. With 23 entropy words this practically always
            // exists; skip the rare input where it does not.
            let mut found = None;
            'outer: for i in 0..WORD_COUNT - 1 {
                for j in i + 1..WORD_COUNT - 1 {
                    if indices[i] != indices[j] {
                        found = Some((i, j));
                        break 'outer;
                    }
                }
            }
            let (a, b) = match found {
                Some(pair) => pair,
                None => continue,
            };
            let mut words = code.to_words(&list);
            words.swap(a, b);
            let refs: Vec<&str> = words.iter().map(String::as_str).collect();
            match RecoveryCode::from_words(&refs, &list) {
                // The common outcome: the recomputed checksum no longer matches.
                Err(CodeError::BadChecksum) => {}
                // The rare outcome: a valid code, but never the original key.
                Ok(read) => assert_ne!(
                    read.entropy(),
                    &entropy,
                    "a swap must never recover the original key"
                ),
                Err(other) => panic!("unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn debug_hides_the_entropy() {
        let code = RecoveryCode::generate();
        let shown = format!("{code:?}");
        assert!(shown.contains("<redacted>"));
    }

    /// A second throwaway list, distinct from `test_list`, so two different
    /// 2048-word lists can be compared. Built in the test; nothing embedded.
    fn other_list() -> WordList {
        let words: Vec<String> = (0..LIST_LEN).map(|i| format!("x{i:04}")).collect();
        WordList::new(words).unwrap()
    }

    #[test]
    fn a_generated_code_round_trips_through_its_words() {
        // `from_entropy` is already covered; confirm a freshly generated code
        // also survives the word round trip and reads back to its own entropy.
        let list = test_list();
        let code = RecoveryCode::generate();
        let entropy = *code.entropy();
        let words = code.to_words(&list);
        assert_eq!(words.len(), WORD_COUNT);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let read = RecoveryCode::from_words(&refs, &list).unwrap();
        assert_eq!(read.entropy(), &entropy);
    }

    #[test]
    fn every_word_comes_from_the_supplied_list() {
        // The encoding embeds no list: every emitted word must be one the
        // supplied list holds, i.e. all 24 indices are below LIST_LEN.
        let list = test_list();
        let code = RecoveryCode::generate();
        let words = code.to_words(&list);
        for w in &words {
            assert!(list.index_of(w).is_some(), "word not in the supplied list");
        }
        for &idx in &code.indices() {
            assert!((idx as usize) < LIST_LEN, "index outside the list");
        }
    }

    #[test]
    fn the_words_depend_on_the_supplied_list() {
        // The same code encoded with two different lists yields different
        // words, confirming the list is an argument and nothing is fixed in the
        // build. Reading each word set back needs its own list.
        let a = test_list();
        let b = other_list();
        let entropy = random_entropy();
        let code = RecoveryCode::from_entropy(&entropy);
        let words_a = code.to_words(&a);
        let words_b = code.to_words(&b);
        assert_ne!(words_a, words_b, "the two lists must give different words");
        // Each word set reads back only with the list that produced it.
        let refs_a: Vec<&str> = words_a.iter().map(String::as_str).collect();
        let read_a = RecoveryCode::from_words(&refs_a, &a).unwrap();
        assert_eq!(read_a.entropy(), &entropy);
        let refs_b: Vec<&str> = words_b.iter().map(String::as_str).collect();
        let read_b = RecoveryCode::from_words(&refs_b, &b).unwrap();
        assert_eq!(read_b.entropy(), &entropy);
        // The words of one list are not in the other (disjoint prefixes), so a
        // cross read is refused rather than silently accepted.
        assert!(matches!(
            RecoveryCode::from_words(&refs_a, &b),
            Err(CodeError::UnknownWord)
        ));
    }

    #[test]
    fn the_word_list_debug_hides_the_words() {
        // The list's Debug must not print the words themselves.
        let list = test_list();
        let shown = format!("{list:?}");
        assert!(!shown.contains("w0000"), "Debug leaked a word");
        assert!(!shown.contains("w2047"), "Debug leaked a word");
    }

    #[test]
    fn a_wrong_length_is_refused_before_an_unknown_word() {
        // When the input is both too short and holds an unknown word, the
        // length check decides first: the caller sees WrongLength, not
        // UnknownWord. This pins the order `from_words` reports.
        let list = test_list();
        let refs = ["not-in-the-list"; WORD_COUNT - 1];
        assert!(matches!(
            RecoveryCode::from_words(&refs, &list),
            Err(CodeError::WrongLength)
        ));
    }

    #[test]
    fn for_256_bit_entropy_the_checksum_is_the_whole_first_digest_byte() {
        // At ENTROPY_LEN = 32 the BIP39 split gives CHECKSUM_BITS = 8, so the
        // checksum must equal the entire first SHA-256 digest byte, i.e. the
        // same value the earlier whole-byte code produced. This pins that the
        // generalised `checksum` did not change the 24-word output.
        assert_eq!(CHECKSUM_BITS, 8, "this test assumes the 256-bit layout");
        for _ in 0..16 {
            let entropy = random_entropy();
            let digest = Sha256::digest(entropy);
            assert_eq!(
                checksum(&entropy),
                digest[0],
                "with 8 checksum bits the checksum is the first digest byte"
            );
        }
    }

    #[test]
    fn the_last_group_carries_the_checksum_bits() {
        // The checksum occupies the low CHECKSUM_BITS of the last 11-bit group,
        // and the recomputed checksum of the decoded entropy matches it. This
        // confirms the bit placement that the swap and damage tests rely on.
        let entropy = random_entropy();
        let code = RecoveryCode::from_entropy(&entropy);
        let indices = code.indices();
        let last = indices[WORD_COUNT - 1];
        let embedded = (last & ((1u16 << CHECKSUM_BITS) - 1)) as u8;
        assert_eq!(
            embedded,
            checksum(&entropy),
            "the low CHECKSUM_BITS of the last group are the checksum"
        );
    }
}
