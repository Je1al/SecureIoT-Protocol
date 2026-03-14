#include "hash.h"

#include <cstddef>

namespace secure_iot {
namespace {

uint64_t rotl64(uint64_t value, unsigned int shift) {
    return (value << shift) | (value >> (64 - shift));
}

uint64_t load64(const std::array<uint8_t, 32>& key, size_t offset) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(key[offset + i]) << (i * 8U);
    }
    return value;
}

uint64_t avalanche(uint64_t value) {
    value ^= value >> 33U;
    value *= 0xFF51AFD7ED558CCDULL;
    value ^= value >> 33U;
    value *= 0xC4CEB9FE1A85EC53ULL;
    value ^= value >> 33U;
    return value;
}

} // namespace

std::array<uint8_t, 16> compute_hash(const std::vector<uint8_t>& data,
                                     const std::array<uint8_t, 32>& key) {
    uint64_t s1 = 0x0123456789ABCDEFULL ^ load64(key, 0);
    uint64_t s2 = 0xFEDCBA9876543210ULL ^ load64(key, 8);
    uint64_t s3 = 0x0F1E2D3C4B5A6978ULL ^ load64(key, 16);
    uint64_t s4 = 0x8877665544332211ULL ^ load64(key, 24);

    for (size_t i = 0; i < data.size(); ++i) {
        uint64_t b = static_cast<uint64_t>(data[i]);
        s1 ^= b + 0x9E3779B97F4A7C15ULL + (s2 << 6U) + (s2 >> 2U);
        s1 = rotl64(s1, 13U) + s3;
        s2 ^= b + 0xC2B2AE3D27D4EB4FULL + (s3 << 7U) + (s3 >> 3U);
        s2 = rotl64(s2, 17U) + s4;
        s3 ^= b + 0x165667B19E3779F9ULL + (s4 << 5U) + (s4 >> 4U);
        s3 = rotl64(s3, 11U) + s1;
        s4 ^= b + 0xD6E8FEB86659FD93ULL + (s1 << 9U) + (s1 >> 5U);
        s4 = rotl64(s4, 19U) + s2;
    }

    uint64_t h1 = avalanche(s1 ^ s3);
    uint64_t h2 = avalanche(s2 ^ s4);

    std::array<uint8_t, 16> out{};
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((h1 >> (i * 8U)) & 0xFFU);
        out[i + 8] = static_cast<uint8_t>((h2 >> (i * 8U)) & 0xFFU);
    }
    return out;
}

} // namespace secure_iot
