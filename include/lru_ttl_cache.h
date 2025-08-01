#pragma once
#include <unordered_map>
#include <list>
#include <chrono>

template <class K, class V>
class LruTtlCache
{
    using Clock = std::chrono::steady_clock;

    struct Entry
    {
        K key;
        V value;
        Clock::time_point expires_at;
    };

public:
    explicit LruTtlCache(size_t capacity) : cap_(capacity) {}

    // Return true on hit. Fills out and ttl_left_sec.
    bool get(const K &key, V &out, uint32_t &ttl_left_sec)
    {
        auto it = map_.find(key);
        if (it == map_.end())
        {
            misses_++;
            return false;
        }

        auto node_it = it->second;
        auto now = Clock::now();
        if (now >= node_it->expires_at)
        {
            items_.erase(node_it);
            map_.erase(it);
            misses_++;
            return false;
        }

        items_.splice(items_.begin(), items_, node_it); // MRU
        out = items_.front().value;
        ttl_left_sec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(items_.front().expires_at - now).count());
        hits_++;
        return true;
    }

    void put(const K &key, const V &val, uint32_t ttl_sec)
    {
        auto exp = Clock::now() + std::chrono::seconds(ttl_sec);
        auto it = map_.find(key);

        if (it != map_.end())
        {
            it->second->value = val;
            it->second->expires_at = exp;
            items_.splice(items_.begin(), items_, it->second);
            return;
        }

        if (items_.size() == cap_)
        {
            auto &last = items_.back();
            map_.erase(last.key);
            items_.pop_back();
        }
        items_.push_front(Entry{key, val, exp});
        map_[key] = items_.begin();
    }

    void purge_expired()
    {
        auto now = Clock::now();
        for (auto it = items_.begin(); it != items_.end();)
        {
            if (now >= it->expires_at)
            {
                map_.erase(it->key);
                it = items_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    size_t hits() const { return hits_; }
    size_t misses() const { return misses_; }
    size_t size() const { return items_.size(); }

private:
    size_t cap_;
    std::list<Entry> items_;
    std::unordered_map<K, typename std::list<Entry>::iterator> map_;
    size_t hits_{0}, misses_{0};
};
