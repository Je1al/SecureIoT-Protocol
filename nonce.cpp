#include "nonce.h"

#include <random>

namespace secure_iot {

std::array<uint8_t, 8> generate_nonce() {
    std::array<uint8_t, 8> nonce{};

    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);

    for (auto& byte : nonce) {
        byte = static_cast<uint8_t>(dist(rd));
    }

    return nonce;
}

} // namespace secure_iot
