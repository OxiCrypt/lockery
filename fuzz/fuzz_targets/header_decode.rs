//! Feed arbitrary bytes to the vault header parser. It must never panic, and
//! anything it accepts must satisfy the invariants `decode` promises.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lockery::crypto::{KdfParams, TAG_LEN};
use lockery::vault::format;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = format::decode(data) {
        let kdf = parsed.header.kdf;
        assert!(kdf.m_cost_kib() <= KdfParams::MAX_M_COST_KIB);
        assert!(kdf.t_cost() <= KdfParams::MAX_T_COST);
        assert!(kdf.p_cost() <= KdfParams::MAX_P_COST);
        assert_eq!(parsed.header.nonce.len(), parsed.header.cipher.nonce_len());
        assert!(parsed.ciphertext.len() >= TAG_LEN);
        assert_eq!(parsed.aad.len() + parsed.ciphertext.len(), data.len());
    }
});
