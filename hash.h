#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace secure_iot {

// Educational 128-bit keyed hash (NOT cryptographically secure).
std::array<uint8_t, 16> compute_hash(const std::vector<uint8_t>& data,
                                     const std::array<uint8_t, 32>& key);

} // namespace secure_iot
