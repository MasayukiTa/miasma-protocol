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

/// The 8-bit checksum of the entropy: the top [`CHECKSUM_BITS`] bits of its
/// SHA-256 digest.
fn checksum(entropy: &[u8; ENTROPY_LEN]) -> u8 {
    let digest = Sha256::digest(entropy);
    // CHECKSUM_BITS is 8, so this is exactly the first digest byte.
    digest[0]
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

    /// The 24 eleven-bit groups of 264 = 256 entropy + 8 checksum bits.
    fn indices(&self) -> [u16; WORD_COUNT] {
        let check = checksum(&self.entropy);
        let mut out = [0u16; WORD_COUNT];
        let mut acc: u32 = 0;
        let mut bits = 0usize;
        let mut w = 0usize;
        let total = ENTROPY_LEN + 1;
        for i in 0..total {
            let byte = if i < ENTROPY_LEN {
                self.entropy[i]
            } else {
                check
            };
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= BITS_PER_WORD {
                bits -= BITS_PER_WORD;
                let idx = ((acc >> bits) & 0x7ff) as u16;
                out[w] = idx;
                w += 1;
            }
        }
        debug_assert_eq!(w, WORD_COUNT);
        debug_assert_eq!(bits, 0);
        out
    }

    /// Reassemble the entropy from 24 indices and verify the checksum.
    fn from_indices(indices: &[u16; WORD_COUNT]) -> Result<Self, CodeError> {
        let mut bytes = Zeroizing::new([0u8; ENTROPY_LEN + 1]);
        let mut acc: u32 = 0;
        let mut bits = 0usize;
        let mut b = 0usize;
        for &idx in indices {
            acc = (acc << BITS_PER_WORD) | u32::from(idx & 0x7ff);
            bits += BITS_PER_WORD;
            while bits >= 8 {
                bits -= 8;
                bytes[b] = ((acc >> bits) & 0xff) as u8;
                b += 1;
            }
        }
        debug_assert_eq!(b, ENTROPY_LEN + 1);
        debug_assert_eq!(bits, 0);
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        entropy.copy_from_slice(&bytes[..ENTROPY_LEN]);
        let want = checksum(&entropy);
        // The checksum byte carries CHECKSUM_BITS meaningful bits; here that is
        // the whole byte.
        let _ = CHECKSUM_BITS;
        if !bool::from(bytes[ENTROPY_LEN].ct_eq(&want)) {
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
        let list = test_list();
        let code = RecoveryCode::generate();
        // Take the correct indices and flip the lowest checksum bit, which lives
        // in the last group. The bytes then no longer match their checksum, so
        // the read must fail rather than return a different valid code.
        let mut indices = code.indices();
        indices[WORD_COUNT - 1] ^= 1;
        let words: Vec<String> = indices.iter().map(|&i| list.word(i).to_string()).collect();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        assert!(matches!(
            RecoveryCode::from_words(&refs, &list),
            Err(CodeError::BadChecksum)
        ));
    }

    #[test]
    fn swapping_two_distinct_words_does_not_recover_the_same_key() {
        // Two different word positions with different indices: swapping them
        // changes the bytes, so the read either fails the checksum or yields a
        // different key. It never returns the original entropy.
        let list = test_list();
        let entropy = random_entropy();
        let code = RecoveryCode::from_entropy(&entropy);
        let indices = code.indices();
        // Find two positions whose indices differ.
        let mut a = 0usize;
        let mut b = 1usize;
        while indices[a] == indices[b] && b < WORD_COUNT - 1 {
            b += 1;
        }
        assert_ne!(indices[a], indices[b], "need two different indices");
        let mut words = code.to_words(&list);
        words.swap(a, b);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        match RecoveryCode::from_words(&refs, &list) {
            Err(CodeError::BadChecksum) => {}
            Ok(read) => assert_ne!(read.entropy(), &entropy),
            Err(other) => panic!("unexpected error: {other}"),
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
}
