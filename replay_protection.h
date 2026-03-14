#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_set>

namespace secure_iot {

// Simple in-memory replay cache with TTL and max size.
class ReplayCache {
public:
    ReplayCache(size_t max_entries = 1024, uint64_t ttl_seconds = 300);

    // Returns true if nonce was seen before (replay). Otherwise stores it and returns false.
    bool is_replay(const std::array<uint8_t, 8>& nonce, uint64_t now_seconds);

private:
    struct Entry {
        std::string nonce_key;
        uint64_t seen_at;
    };

    void prune(uint64_t now_seconds);
    std::string nonce_to_key(const std::array<uint8_t, 8>& nonce) const;

    size_t max_entries_;
    uint64_t ttl_seconds_;
    std::deque<Entry> order_;
    std::unordered_set<std::string> seen_;
};

} // namespace secure_iot
