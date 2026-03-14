#include "packet.h"

#include <cstddef>

namespace secure_iot {
namespace {

void append_u32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFU));
    }
}

void append_u64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFU));
    }
}

bool read_u32(const std::vector<uint8_t>& data, size_t& offset, uint32_t& value) {
    if (offset + 4 > data.size()) {
        return false;
    }
    value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8) | static_cast<uint32_t>(data[offset + i]);
    }
    offset += 4;
    return true;
}

bool read_u64(const std::vector<uint8_t>& data, size_t& offset, uint64_t& value) {
    if (offset + 8 > data.size()) {
        return false;
    }
    value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<uint64_t>(data[offset + i]);
    }
    offset += 8;
    return true;
}

} // namespace

std::vector<uint8_t> serialize_packet(const PacketHeader& header,
                                      const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> out;
    out.reserve(16 + ciphertext.size());

    out.insert(out.end(), header.nonce.begin(), header.nonce.end());
    append_u64(out, header.timestamp);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    return out;
}

bool deserialize_packet(const std::vector<uint8_t>& data,
                        PacketHeader& header,
                        std::vector<uint8_t>& ciphertext) {
    if (data.size() < 16) {
        return false;
    }

    size_t offset = 0;
    for (size_t i = 0; i < header.nonce.size(); ++i) {
        header.nonce[i] = data[offset + i];
    }
    offset += header.nonce.size();

    if (!read_u64(data, offset, header.timestamp)) {
        return false;
    }

    ciphertext.assign(data.begin() + static_cast<long>(offset), data.end());
    return !ciphertext.empty();
}

std::vector<uint8_t> serialize_payload(const std::string& message,
                                       const std::array<uint8_t, 16>& hash) {
    std::vector<uint8_t> out;
    out.reserve(4 + message.size() + hash.size());

    append_u32(out, static_cast<uint32_t>(message.size()));
    out.insert(out.end(), message.begin(), message.end());
    out.insert(out.end(), hash.begin(), hash.end());

    return out;
}

bool deserialize_payload(const std::vector<uint8_t>& data,
                         std::string& message,
                         std::array<uint8_t, 16>& hash) {
    size_t offset = 0;
    uint32_t message_len = 0;

    if (!read_u32(data, offset, message_len)) {
        return false;
    }

    if (offset + message_len + hash.size() != data.size()) {
        return false;
    }

    message.assign(reinterpret_cast<const char*>(&data[offset]), message_len);
    offset += message_len;

    for (size_t i = 0; i < hash.size(); ++i) {
        hash[i] = data[offset + i];
    }

    return true;
}

std::vector<uint8_t> build_hash_input(const std::string& message,
                                      const std::array<uint8_t, 8>& nonce,
                                      uint64_t timestamp) {
    std::vector<uint8_t> data;
    data.reserve(message.size() + nonce.size() + 8);

    data.insert(data.end(), message.begin(), message.end());
    data.insert(data.end(), nonce.begin(), nonce.end());
    append_u64(data, timestamp);

    return data;
}

} // namespace secure_iot
