#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace secure_iot {

struct PacketHeader {
    std::array<uint8_t, 8> nonce;  // Random nonce (sent in clear header)
    uint64_t timestamp;            // Unix epoch seconds
};

// Packet format (header in clear, payload encrypted):
// [8 bytes nonce][8 bytes timestamp][ciphertext...]
std::vector<uint8_t> serialize_packet(const PacketHeader& header,
                                      const std::vector<uint8_t>& ciphertext);
bool deserialize_packet(const std::vector<uint8_t>& data,
                        PacketHeader& header,
                        std::vector<uint8_t>& ciphertext);

// Payload format (encrypted):
// [4 bytes message_len][message][16 bytes hash]
std::vector<uint8_t> serialize_payload(const std::string& message,
                                       const std::array<uint8_t, 16>& hash);
bool deserialize_payload(const std::vector<uint8_t>& data,
                         std::string& message,
                         std::array<uint8_t, 16>& hash);

// Hash input builder: message + nonce + timestamp.
std::vector<uint8_t> build_hash_input(const std::string& message,
                                      const std::array<uint8_t, 8>& nonce,
                                      uint64_t timestamp);

} // namespace secure_iot
