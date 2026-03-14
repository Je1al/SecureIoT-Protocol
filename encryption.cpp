#include "encryption.h"

#include <cstddef>

namespace secure_iot {
namespace {

constexpr uint64_t kMixConstant = 0x9E3779B97F4A7C15ULL; // 2^64 * golden ratio

uint64_t rotl64(uint64_t value, unsigned int shift) {
    return (value << shift) | (value >> (64 - shift));
}

uint64_t mix_material(const std::array<uint8_t, 32>& key,
                      const std::array<uint8_t, 8>& nonce,
                      uint64_t timestamp) {
    // Fold key, nonce, and timestamp into a 64-bit state.
    uint64_t state = 0x6A09E667F3BCC909ULL ^ timestamp;
    auto mix_byte = [&](uint8_t byte) {
        state ^= static_cast<uint64_t>(byte) + kMixConstant + (state << 6) + (state >> 2);
        state = rotl64(state, 13) * 0x100000001B3ULL;
    };

    for (uint8_t byte : key) {
        mix_byte(byte);
    }
    for (uint8_t byte : nonce) {
        mix_byte(byte);
    }
    for (int i = 0; i < 8; ++i) {
        mix_byte(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFFU));
    }

    return state;
}

std::vector<uint8_t> xor_stream(const std::vector<uint8_t>& input,
                                const std::array<uint8_t, 32>& key,
                                const std::array<uint8_t, 8>& nonce,
                                uint64_t timestamp) {
    std::vector<uint8_t> output(input.size());
    uint64_t state = mix_material(key, nonce, timestamp);

    for (size_t i = 0; i < input.size(); ++i) {
        // XorShift + rotation to generate a pseudo-random keystream byte.
        state ^= (state >> 12);
        state ^= (state << 25);
        state ^= (state >> 27);
        state = rotl64(state + kMixConstant + static_cast<uint64_t>(i), 17);
        state *= 0x2545F4914F6CDD1DULL;

        uint8_t keystream = static_cast<uint8_t>(state >> ((i % 8) * 8));
        output[i] = static_cast<uint8_t>(input[i] ^ keystream);
    }

    return output;
}

} // namespace

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                             const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 8>& nonce,
                             uint64_t timestamp) {
    return xor_stream(plaintext, key, nonce, timestamp);
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                             const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 8>& nonce,
                             uint64_t timestamp) {
    return xor_stream(ciphertext, key, nonce, timestamp);
}

} // namespace secure_iot
