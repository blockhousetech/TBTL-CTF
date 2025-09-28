use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use unicode_segmentation::UnicodeSegmentation;

const HAYSTACK: &[u8] = include_bytes!("../haystack.bin");
const NONCE: &[u8; 12] = b"*chirpchirp*";

const CIPHERTEXT: &[u8] = &[
    0x4D, 0x34, 0xA2, 0x98, 0x70, 0x73, 0xDB, 0xB8, 0x66, 0xAE, 0x2C, 0xC4, 0x9B, 0x89, 0xC9, 0xFF,
    0x4F, 0xD5, 0x83, 0xD0, 0x54, 0xDC, 0x51, 0xB9, 0xC0, 0x6D, 0xEF, 0x5D, 0xB1, 0x97, 0xBB, 0xC7,
    0x14, 0xFD, 0xDC, 0x96, 0xFB, 0x1C, 0xF1, 0x66, 0x3C, 0xAE, 0x19, 0x02, 0x12, 0xD7, 0xA1, 0x94,
    0x53, 0xFC, 0xD0, 0x5B, 0x1D, 0x3A, 0xA6, 0xBF, 0xD3, 0x45, 0x14, 0x71, 0xAF, 0x36, 0x5B, 0xB6,
    0x23, 0x80, 0x33, 0xCE, 0xD7, 0x24, 0x43, 0xE8, 0x83, 0x98, 0xCD, 0xB8, 0x68, 0xF9, 0x48, 0x30,
    0x77, 0xEB, 0xAE, 0xDC,
];

fn vs_to_byte(ch: char) -> Option<u8> {
    match ch as u32 {
        0xFE00..=0xFE0F => Some((ch as u32 - 0xFE00) as u8),
        0xE0100..=0xE01EF => Some((ch as u32 - 0xE0100 + 16) as u8),
        _ => None,
    }
}

fn decode_vs(cluster: &str) -> Vec<u8> {
    cluster.chars().skip(1).filter_map(vs_to_byte).collect()
}

fn haystack_contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn main() -> io::Result<()> {
    println!("🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦🐦");
    println!("These birds... they can't be here just for decoration.");
    print!("Can you find the right one? ");
    io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim_end();

    let mut g = trimmed.graphemes(true);
    if let (Some(cluster), None) = (g.next(), g.next()) {
        if haystack_contains(HAYSTACK, trimmed.as_bytes()) {
            let phrase_bytes = decode_vs(cluster);
            let key = &Sha256::digest(phrase_bytes)[..16];
            let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
            if let Ok(pt) = cipher.decrypt(Nonce::from_slice(NONCE), CIPHERTEXT) {
                if pt.starts_with(b"FortID{") {
                    println!("{}", String::from_utf8_lossy(&pt));
                    return Ok(());
                }
            }
        }
    }
    println!("Nope.");
    Ok(())
}
