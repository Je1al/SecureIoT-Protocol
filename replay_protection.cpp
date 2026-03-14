#include "replay_protection.h"

namespace secure_iot {

ReplayCache::ReplayCache(size_t max_entries, uint64_t ttl_seconds)
    : max_entries_(max_entries), ttl_seconds_(ttl_seconds) {}

bool ReplayCache::is_replay(const std::array<uint8_t, 8>& nonce, uint64_t now_seconds) {
    prune(now_seconds);

    const std::string key = nonce_to_key(nonce);
    if (seen_.find(key) != seen_.end()) {
        return true;
    }

    seen_.insert(key);
    order_.push_back({key, now_seconds});

    if (order_.size() > max_entries_) {
        auto& oldest = order_.front();
        seen_.erase(oldest.nonce_key);
        order_.pop_front();
    }

    return false;
}

void ReplayCache::prune(uint64_t now_seconds) {
    if (!order_.empty() && now_seconds < order_.front().seen_at) {
        // Clock moved backwards; reset cache to avoid underflow.
        seen_.clear();
        order_.clear();
        return;
    }

    while (!order_.empty()) {
        const auto& entry = order_.front();
        if (now_seconds - entry.seen_at <= ttl_seconds_) {
            break;
        }
        seen_.erase(entry.nonce_key);
        order_.pop_front();
    }
}

std::string ReplayCache::nonce_to_key(const std::array<uint8_t, 8>& nonce) const {
    return std::string(reinterpret_cast<const char*>(nonce.data()), nonce.size());
}

} // namespace secure_iot
