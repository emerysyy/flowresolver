#include "port_matcher.h"
#include <new>
#include <cstring>
#include <thread>

thread_local flow::PortMatcher::ThreadRecord* flow::PortMatcher::tls_record_ = nullptr;

namespace flow {

// =======================
// ctor / dtor
// =======================

PortMatcher::PortMatcher()
{
    LUT* lut = new LUT{};
    active_.store(lut, std::memory_order_release);
}

PortMatcher::~PortMatcher()
{
    // reclaim everything (best-effort)
    for (auto& r : retired_) {
        delete r.ptr;
    }
    retired_.clear();

    LUT* lut = active_.load(std::memory_order_acquire);
    delete lut;

    // ThreadRecord 泄漏是 classic EBR 的已知 trade-off
}

// =======================
// EBR helpers
// =======================

void PortMatcher::register_thread() const
{
    if (tls_record_) {
        return;
    }

    ThreadRecord* rec = new ThreadRecord{};
    ThreadRecord* old_head;

    do {
        old_head = thread_list_.load(std::memory_order_relaxed);
        rec->next = old_head;
    } while (!thread_list_.compare_exchange_weak(
        old_head,
        rec,
        std::memory_order_release,
        std::memory_order_relaxed));

    tls_record_ = rec;
}

void PortMatcher::enter_epoch() const noexcept
{
    if (!tls_record_) {
        register_thread();
    }

    uint64_t e = global_epoch_.load(std::memory_order_acquire);
    tls_record_->epoch.store(e, std::memory_order_release);
    tls_record_->active.store(true, std::memory_order_release);

    // 关键：release fence，保证 epoch 先于后续指针 load 被看到
    std::atomic_thread_fence(std::memory_order_release);
}

void PortMatcher::exit_epoch() const noexcept
{
    tls_record_->active.store(false, std::memory_order_release);
    tls_record_->epoch.store(0, std::memory_order_release);
}

void PortMatcher::retire_lut(LUT* lut, uint64_t epoch)
{
    retired_.push_back({lut, epoch});

    if (retired_.size() >= kMaxRetired) {
        try_reclaim();
    }
}

void PortMatcher::try_reclaim()
{
    uint64_t min_epoch = UINT64_MAX;
    bool has_active = false;

    ThreadRecord* cur = thread_list_.load(std::memory_order_acquire);
    while (cur) {
        if (cur->active.load(std::memory_order_acquire)) {
            uint64_t e = cur->epoch.load(std::memory_order_acquire);
            if (e != 0) {
                min_epoch = std::min(min_epoch, e);
                has_active = true;
            }
        }
        cur = cur->next;
    }

    // 没有任何活跃读者：全部安全
    if (!has_active) {
        for (auto& r : retired_) {
            delete r.ptr;
        }
        retired_.clear();
        return;
    }

    // 只回收 retired_epoch < min_epoch 的
    auto it = retired_.begin();
    while (it != retired_.end()) {
        if (it->retired_epoch < min_epoch) {
            delete it->ptr;
            it = retired_.erase(it);
        } else {
            ++it;
        }
    }
}

// =======================
// match (read path)
// =======================

std::vector<RuleId>
PortMatcher::match(uint16_t port) const
{
    enter_epoch();

    LUT* lut = active_.load(std::memory_order_acquire);
    std::vector<RuleId> result;

    if (lut) {
        const auto& rl = lut->ports[port];
        if (rl.data && rl.size > 0) {
            result.assign(rl.data, rl.data + rl.size);
        }
    }

    exit_epoch();
    return result;
}

// =======================
// rebuild (write path)
// =======================

PortMatcher::LUT*
PortMatcher::build_lut(const std::vector<Rule>& rules)
{
    LUT* lut = new LUT{};

    // 临时收集
    std::vector<RuleId> tmp[65536];

    for (const auto& r : rules) {
        uint16_t b = r.begin;
        uint16_t e = r.end;
        if (b > e) std::swap(b, e);
        if (b > 65535) continue;
        if (e > 65535) e = 65535;

        for (uint32_t p = b; p <= e; ++p) {
            tmp[p].push_back(r.ruleId);
        }
    }

    for (uint32_t p = 0; p < 65536; ++p) {
        if (tmp[p].empty()) continue;

        auto& v = tmp[p];
        std::sort(v.begin(), v.end());

        RuleId* data = new RuleId[v.size()];
        std::memcpy(data, v.data(), v.size() * sizeof(RuleId));

        lut->ports[p].data = data;
        lut->ports[p].size = static_cast<uint32_t>(v.size());
    }

    return lut;
}

void PortMatcher::rebuild(const std::vector<Rule>& rules)
{
    LUT* next = build_lut(rules);

    // old epoch（用于 retire）
    uint64_t retire_epoch =
        global_epoch_.load(std::memory_order_acquire);

    // 推进 epoch
    global_epoch_.fetch_add(1, std::memory_order_acq_rel);

    LUT* old = active_.exchange(next, std::memory_order_acq_rel);
    retire_lut(old, retire_epoch);
}

} // namespace flow