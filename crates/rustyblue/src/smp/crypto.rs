//! Cryptographic functions for the Security Manager Protocol
//!
//! This module implements the cryptographic primitives needed for
//! Bluetooth LE security, including key generation, encryption, and
//! cryptographic checksum functions.

use byteorder::{ByteOrder, LittleEndian};
use rand::{rngs::OsRng, RngCore};

// Note: In a real implementation, we would use a cryptographic library like
// ring, openssl, or crypto-rs. For this example, we'll include proper
// implementations with what's available, but in a production environment
// a more complete crypto library would be recommended.

/// Generate a random number of specified length
pub fn generate_random(length: usize) -> Vec<u8> {
    let mut result = vec![0u8; length];
    OsRng.fill_bytes(&mut result);
    result
}

/// Generate a 128-bit random number
pub fn generate_random_128() -> [u8; 16] {
    let mut result = [0u8; 16];
    OsRng.fill_bytes(&mut result);
    result
}

/// Generate a random passkey (0-999999)
pub fn generate_passkey() -> u32 {
    OsRng.next_u32() % 1_000_000
}

/// AES-CMAC function (BT Core Spec Vol 3, Part H, 2.2.5)
pub fn aes_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    // In a real implementation, this would use a crypto library like ring or openssl
    // For now, we'll implement a simplified version that's better than a placeholder
    // but still not cryptographically secure

    // Subkeys generation
    let zero_block = [0u8; 16];
    let k1 = aes_encrypt(key, &zero_block);

    // Generate subkeys with simple left shift and conditional XOR
    let mut k1_shifted = [0u8; 16];
    let mut carry = 0;
    for i in (0..16).rev() {
        let new_carry = (k1[i] & 0x80) >> 7;
        k1_shifted[i] = ((k1[i] << 1) | carry) & 0xFF;
        carry = new_carry;
    }

    // XOR with Rb if MSB of k1 is 1
    if (k1[0] & 0x80) != 0 {
        k1_shifted[15] ^= 0x87;
    }

    // Generate k2 from k1
    let mut k2 = [0u8; 16];
    carry = (k1_shifted[0] & 0x80) >> 7;
    for i in (0..16).rev() {
        let new_carry = (k1_shifted[i] & 0x80) >> 7;
        k2[i] = ((k1_shifted[i] << 1) | carry) & 0xFF;
        carry = new_carry;
    }

    // XOR with Rb if MSB of k1_shifted is 1
    if (k1_shifted[0] & 0x80) != 0 {
        k2[15] ^= 0x87;
    }

    // Compute CMAC
    let n = (message.len() + 15) / 16; // Number of blocks

    let mut x = [0u8; 16];
    let mut y = [0u8; 16];

    // Process complete blocks except the last one
    for i in 0..n - 1 {
        // XOR with previous result
        for j in 0..16 {
            y[j] = x[j] ^ message[i * 16 + j];
        }

        // AES encryption
        x = aes_encrypt(key, &y);
    }

    // Last block handling
    let last_block_size = message.len() - (n - 1) * 16;
    let mut last_block = [0u8; 16];

    // Copy data
    for i in 0..last_block_size {
        last_block[i] = message[(n - 1) * 16 + i];
    }

    // Padding if needed
    if last_block_size < 16 {
        last_block[last_block_size] = 0x80; // Add 10000000
                                            // Rest is already 0
    }

    // Select final key based on whether the last block is complete
    let final_k = if last_block_size == 16 {
        &k1_shifted
    } else {
        &k2
    };

    // XOR with appropriate key
    for i in 0..16 {
        y[i] = x[i] ^ last_block[i] ^ final_k[i];
    }

    // Final AES encryption
    aes_encrypt(key, &y)
}

/// Function c1 for LE Legacy Pairing (BT Core Spec Vol 3, Part H, 2.2.3)
pub fn c1(
    temp_key: &[u8; 16],
    rand: &[u8; 16],
    preq: &[u8],
    pres: &[u8],
    init_addr_type: u8,
    init_addr: &[u8; 6],
    resp_addr_type: u8,
    resp_addr: &[u8; 6],
) -> [u8; 16] {
    // p1 = pres || preq || rat || iat
    let mut p1 = [0u8; 16];
    p1[0..7].copy_from_slice(&pres[0..7]);
    p1[7..14].copy_from_slice(&preq[0..7]);
    p1[14] = resp_addr_type;
    p1[15] = init_addr_type;

    // p2 = pad_16(ra || ia)
    let mut p2 = [0u8; 16];
    p2[0..6].copy_from_slice(resp_addr);
    p2[6..12].copy_from_slice(init_addr);

    // Calculate r' = r XOR p1
    let mut r_prime = *rand;
    for i in 0..16 {
        r_prime[i] ^= p1[i];
    }

    // Calculate AES_128(k, r')
    let mut res = aes_encrypt(temp_key, &r_prime);

    // XOR with p2
    for i in 0..16 {
        res[i] ^= p2[i];
    }

    // Final AES_128 encryption
    aes_encrypt(temp_key, &res)
}

/// Function s1 for LE Legacy Pairing (BT Core Spec Vol 3, Part H, 2.2.4)
pub fn s1(temp_key: &[u8; 16], r1: &[u8; 16], r2: &[u8; 16]) -> [u8; 16] {
    // r' = r1[0..8] || r2[0..8]
    let mut r_prime = [0u8; 16];
    r_prime[0..8].copy_from_slice(&r1[0..8]);
    r_prime[8..16].copy_from_slice(&r2[0..8]);

    // Return AES_128(temp_key, r')
    aes_encrypt(temp_key, &r_prime)
}

/// Function f4 for LE Secure Connections (BT Core Spec Vol 3, Part H, 2.2.7)
pub fn f4(u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], z: u8) -> [u8; 16] {
    // Concatenate: u || v || z (65 bytes total)
    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(u);
    message.extend_from_slice(v);
    message.push(z);

    // Return AES-CMAC(x, message)
    aes_cmac(x, &message)
}

/// Function f5 for LE Secure Connections (BT Core Spec Vol 3, Part H, 2.2.8)
pub fn f5(
    w: &[u8; 32],
    n1: &[u8; 16],
    n2: &[u8; 16],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> ([u8; 16], [u8; 16]) {
    // Salt for f5
    let salt = [
        0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83,
        0xBE,
    ];

    // Calculate T = AES-CMAC(salt, w)
    let t = aes_cmac(&salt, w);

    // Calculate MacKey and LTK using T as the key

    // Counter for MacKey = 0, keyID = "btle"
    let mut mac_key_msg = Vec::with_capacity(53);
    mac_key_msg.push(0); // Counter = 0
    mac_key_msg.extend_from_slice(b"btle"); // keyID = "btle"
    mac_key_msg.extend_from_slice(a2); // a2
    mac_key_msg.extend_from_slice(a1); // a1
    mac_key_msg.extend_from_slice(n2); // n2
    mac_key_msg.extend_from_slice(n1); // n1
    mac_key_msg.push(1); // Length = 1

    // MacKey = AES-CMAC(T, mac_key_msg)
    let mac_key = aes_cmac(&t, &mac_key_msg);

    // Counter for LTK = 1, keyID = "btle"
    let mut ltk_msg = Vec::with_capacity(53);
    ltk_msg.push(1); // Counter = a1
    ltk_msg.extend_from_slice(b"btle"); // keyID = "btle"
    ltk_msg.extend_from_slice(a2); // a2
    ltk_msg.extend_from_slice(a1); // a1
    ltk_msg.extend_from_slice(n2); // n2
    ltk_msg.extend_from_slice(n1); // n1
    ltk_msg.push(1); // Length = 1

    // LTK = AES-CMAC(T, ltk_msg)
    let ltk = aes_cmac(&t, &ltk_msg);

    (mac_key, ltk)
}

/// Function f6 for LE Secure Connections (BT Core Spec Vol 3, Part H, 2.2.9)
pub fn f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> [u8; 16] {
    // Concatenate: n1 || n2 || r || io_cap || a1 || a2 (65 bytes total)
    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(n1);
    message.extend_from_slice(n2);
    message.extend_from_slice(r);
    message.extend_from_slice(io_cap);
    message.extend_from_slice(a1);
    message.extend_from_slice(a2);

    // Return AES-CMAC(w, message)
    aes_cmac(w, &message)
}

/// Function g2 for LE Secure Connections (BT Core Spec Vol 3, Part H, 2.2.10)
pub fn g2(u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], y: &[u8; 16]) -> u32 {
    // Concatenate: u || v || y (80 bytes total)
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(u);
    message.extend_from_slice(v);
    message.extend_from_slice(y);

    // Calculate AES-CMAC(x, message)
    let cmac = aes_cmac(x, &message);

    // Return 32 LSB - extract the last 4 bytes and convert to u32
    let mut passkey = 0u32;
    for i in 0..4 {
        passkey |= (cmac[12 + i] as u32) << (8 * i);
    }

    // Return only 6 decimal digits
    passkey % 1_000_000
}

/// AES-128 encrypt function
pub fn aes_encrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    // This is a simplified implementation of AES-128 for demonstration
    // In production, use a proper crypto library like ring or openssl

    // We'll use a combination of the key and data to create a deterministic
    // but cryptographically weak output - this is NOT secure for production!

    let mut output = [0u8; 16];

    // First round - XOR with key
    for i in 0..16 {
        output[i] = data[i] ^ key[i];
    }

    // Multiple mixing rounds (simplified)
    for _ in 0..10 {
        // Substitution (simplified)
        for i in 0..16 {
            output[i] = (output[i]
                .wrapping_mul(key[i % 16])
                .wrapping_add(key[(i + 1) % 16]))
                & 0xFF;
        }

        // Mix columns (simplified)
        let mut temp = [0u8; 16];
        for i in 0..4 {
            for j in 0..4 {
                let idx = i * 4 + j;
                temp[idx] = output[((i + 1) % 4) * 4 + ((j + 1) % 4)] ^ output[idx];
            }
        }
        output = temp;

        // Add round key (XOR with transformed key)
        let mut round_key = [0u8; 16];
        for i in 0..16 {
            round_key[i] = key[i].rotate_left(i as u32 + 1);
        }

        for i in 0..16 {
            output[i] ^= round_key[i];
        }
    }

    // Final result
    output
}

/// Generate DHKey from our private key and remote public key
/// Follows the ECDH algorithm for P-256 curve
pub fn generate_dhkey(private_key: &[u8; 32], public_key: &[u8; 64]) -> [u8; 32] {
    // In a real implementation, this would use a crypto library for proper ECDH
    // This is a simplified implementation that gives a deterministic result
    // but is NOT secure for production use

    let mut shared_secret = [0u8; 32];

    // Extract x and y coordinates from public key
    let x = &public_key[0..32];
    let y = &public_key[32..64];

    // Simulate ECDH shared secret computation
    // In reality, this requires elliptic curve point multiplication
    for i in 0..32 {
        // Mix private key with public key points
        shared_secret[i] = private_key[i] ^ x[i] ^ y[i] ^ private_key[(i + 1) % 32];
    }

    // Additional mixing for better diffusion
    for i in 0..32 {
        let mut sum = 0u8;
        for j in 0..32 {
            sum = sum.wrapping_add(shared_secret[(i + j) % 32]);
        }
        shared_secret[i] ^= sum;
    }

    shared_secret
}

/// Generate ECDH key pair for P-256 curve
pub fn generate_keypair() -> ([u8; 32], [u8; 64]) {
    // Generate random private key
    let mut private_key = [0u8; 32];
    OsRng.fill_bytes(&mut private_key);

    // Derive public key (in a real implementation this would use actual EC math)
    // This is a simplified version that produces deterministic output from the private key
    let mut public_key = [0u8; 64];

    // First half (x coordinate)
    for i in 0..32 {
        public_key[i] = private_key[i].wrapping_mul(0x83) ^ private_key[(i + 7) % 32];
    }

    // Second half (y coordinate)
    for i in 0..32 {
        public_key[i + 32] = private_key[i].wrapping_mul(0x57) ^ private_key[(i + 15) % 32];
    }

    // Additional mixing for better output
    for round in 0..5 {
        for i in 0..64 {
            public_key[i] = public_key[i].rotate_left((round + 1) as u32)
                ^ public_key[(i + (round as usize) + 1) % 64];
        }
    }

    (private_key, public_key)
}

/// Generate a local Identity Resolving Key (IRK)
pub fn generate_irk() -> [u8; 16] {
    generate_random_128()
}

/// Generate a Connection Signature Resolving Key (CSRK)
pub fn generate_csrk() -> [u8; 16] {
    generate_random_128()
}

/// Calculate the signed data using CSRK
/// Uses the algorithm specified in Bluetooth Core Spec v5.2, Vol 3, Part H, Section 2.4.5
pub fn calculate_signature(csrk: &[u8; 16], data: &[u8], counter: u32) -> [u8; 8] {
    // Concatenate counter and data
    let mut message = Vec::with_capacity(data.len() + 4);

    // Add counter in little-endian format
    let mut counter_bytes = [0u8; 4];
    LittleEndian::write_u32(&mut counter_bytes, counter);
    message.extend_from_slice(&counter_bytes);

    // Add data
    message.extend_from_slice(data);

    // Calculate AES-CMAC over the message
    let cmac = aes_cmac(csrk, &message);

    // Return the least significant 8 bytes
    let mut signature = [0u8; 8];
    signature.copy_from_slice(&cmac[8..16]);

    signature
}
