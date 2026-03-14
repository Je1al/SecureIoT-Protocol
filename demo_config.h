#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace secure_iot {

// Shared symmetric key for demo purposes.
// In real deployments, store/derive this via secure provisioning.
inline constexpr std::array<uint8_t, 32> kSharedKey = {
    0x53, 0x49, 0x4F, 0x54, 0x2D, 0x53, 0x65, 0x63,
    0x75, 0x72, 0x65, 0x2D, 0x4B, 0x65, 0x79, 0x2D,
    0x44, 0x65, 0x6D, 0x6F, 0x2D, 0x32, 0x30, 0x32,
    0x36, 0x2D, 0x4B, 0x65, 0x79, 0x21, 0x00, 0x01
};

// Acceptable clock skew (seconds) for timestamp freshness checks.
constexpr uint64_t kMaxClockSkewSeconds = 120;

// How long to keep seen nonces (seconds).
constexpr uint64_t kNonceTtlSeconds = 600;

// Replay cache size (entries).
constexpr std::size_t kReplayCacheMaxEntries = 2048;

// Nonce size (bytes).
constexpr std::size_t kNonceSizeBytes = 8;

} // namespace secure_iot
