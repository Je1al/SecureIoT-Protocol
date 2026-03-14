#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace secure_iot {

// XOR-based stream encryption with key mixing and bit rotations.
// Educational only: not a substitute for AES/ChaCha20.
std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                             const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 8>& nonce,
                             uint64_t timestamp);

// XOR stream encryption is symmetric, so decrypt == encrypt.
std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                             const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 8>& nonce,
                             uint64_t timestamp);

} // namespace secure_iot
