#pragma once

#include <array>

namespace secure_iot {

// Generates a random nonce. For real embedded deployments, use hardware RNG.
std::array<uint8_t, 8> generate_nonce();

} // namespace secure_iot
