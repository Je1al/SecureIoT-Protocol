#include "demo_config.h"
#include "encryption.h"
#include "hash.h"
#include "nonce.h"
#include "packet.h"
#include "utils.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

namespace {

uint64_t now_seconds() {
    const auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace secure_iot;

    std::string message = "temperature=22.5C";
    if (argc > 1) {
        message = argv[1];
    }

    const std::string out_path = (argc > 2) ? argv[2] : "packet.bin";

    const uint64_t timestamp = now_seconds();
    const auto nonce = generate_nonce();

    // Integrity binds message + nonce + timestamp with a keyed hash.
    const auto hash_input = build_hash_input(message, nonce, timestamp);
    const auto integrity_hash = compute_hash(hash_input, kSharedKey);

    const auto payload = serialize_payload(message, integrity_hash);
    const auto ciphertext = encrypt(payload, kSharedKey, nonce, timestamp);

    const PacketHeader header{nonce, timestamp};
    const auto packet = serialize_packet(header, ciphertext);

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to open output file: " << out_path << "\n";
        return 1;
    }

    out.write(reinterpret_cast<const char*>(packet.data()),
              static_cast<std::streamsize>(packet.size()));

    std::cout << "[sender] Message: " << message << "\n";
    std::cout << "[sender] Timestamp: " << timestamp << "\n";
    std::cout << "[sender] Nonce: " << to_hex(nonce) << "\n";
    std::cout << "[sender] Hash: " << to_hex(integrity_hash) << "\n";
    std::cout << "[sender] Packet bytes: " << packet.size() << "\n";
    std::cout << "[sender] Ciphertext (hex): " << to_hex(ciphertext) << "\n";
    std::cout << "[sender] Packet written to " << out_path << "\n";

    return 0;
}
