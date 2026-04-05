//! Cryptographically secure recovery phrase generator using BIP39 standard
//! Generates 24-word mnemonic phrases

use bip39::{Mnemonic, Language};
use rand::RngCore;

/// Generates a cryptographically secure 24-word BIP39 mnemonic phrase
/// Returns a tuple of (mnemonic_string, entropy_bytes)
pub fn generate_recovery_phrase() -> (String, Vec<u8>) {
    // Generate 32 bytes of entropy (256 bits) for 24 words
    let mut entropy = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to create mnemonic");
    // In bip39 2.2.2, Mnemonic implements Display and AsRef<str>
    let phrase = mnemonic.to_string();
    
    (phrase, entropy)
}

/// Validates a mnemonic phrase
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    // Try to parse the mnemonic
    match Mnemonic::parse_in_normalized(Language::English, mnemonic) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mnemonic_generation() {
        let (phrase, entropy) = generate_recovery_phrase();
        let word_count = phrase.split_whitespace().count();
        println!("Generated {} words: {}", word_count, phrase);
        assert_eq!(word_count, 24);
        assert!(validate_mnemonic(&phrase));
        assert_eq!(entropy.len(), 32); // 256 bits = 32 bytes
    }
    
    #[test]
    fn test_invalid_mnemonic() {
        assert!(!validate_mnemonic("invalid phrase test"));
    }
}
