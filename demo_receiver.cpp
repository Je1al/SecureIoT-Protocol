#include "demo_config.h"
#include "encryption.h"
#include "hash.h"
#include "packet.h"
#include "replay_protection.h"
#include "utils.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file: " + path);
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    return buffer;
}

uint64_t now_seconds() {
    const auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
}

bool process_packet(const std::vector<uint8_t>& packet_bytes,
                    secure_iot::ReplayCache& cache) {
    using namespace secure_iot;

    PacketHeader header{};
    std::vector<uint8_t> ciphertext;
    if (!deserialize_packet(packet_bytes, header, ciphertext)) {
        std::cerr << "[receiver] Packet parsing failed: malformed header\n";
        return false;
    }

    const auto payload = decrypt(ciphertext, kSharedKey, header.nonce, header.timestamp);

    std::string message;
    std::array<uint8_t, 16> received_hash{};
    if (!deserialize_payload(payload, message, received_hash)) {
        std::cerr << "[receiver] Packet parsing failed: malformed payload\n";
        return false;
    }

    // Verify integrity (tamper detection).
    const auto hash_input = build_hash_input(message, header.nonce, header.timestamp);
    const auto expected_hash = compute_hash(hash_input, kSharedKey);

    if (!constant_time_equals(received_hash, expected_hash)) {
        std::cerr << "[receiver] Hash mismatch! Message tampering suspected.\n";
        return false;
    }

    // Verify timestamp freshness (replay window).
    const uint64_t now = now_seconds();
    const uint64_t delta = (now > header.timestamp)
        ? (now - header.timestamp)
        : (header.timestamp - now);

    if (delta > kMaxClockSkewSeconds) {
        std::cerr << "[receiver] Timestamp not fresh (delta=" << delta << "s).\n";
        return false;
    }

    // Check nonce uniqueness (replay/duplicate detection).
    if (cache.is_replay(header.nonce, now)) {
        std::cerr << "[receiver] Replay detected (nonce already seen).\n";
        return false;
    }

    std::cout << "[receiver] Packet accepted\n";
    std::cout << "[receiver] Timestamp: " << header.timestamp << "\n";
    std::cout << "[receiver] Nonce: " << to_hex(header.nonce) << "\n";
    std::cout << "[receiver] Hash: " << to_hex(received_hash) << "\n";
    std::cout << "[receiver] Message: " << message << "\n";

    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace secure_iot;

    const std::string in_path = (argc > 1) ? argv[1] : "packet.bin";
    const bool replay_demo = (argc > 2 && std::string(argv[2]) == "--replay");

    std::vector<uint8_t> packet_bytes;
    try {
        packet_bytes = read_file(in_path);
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }

    ReplayCache cache(kReplayCacheMaxEntries, kNonceTtlSeconds);

    std::cout << "[receiver] Packet bytes: " << packet_bytes.size() << "\n";
    const bool first_ok = process_packet(packet_bytes, cache);

    if (replay_demo) {
        std::cout << "[receiver] Replaying the same packet to demonstrate detection...\n";
        (void)process_packet(packet_bytes, cache);
    }

    return first_ok ? 0 : 2;
}
