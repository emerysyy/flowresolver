#pragma once

#include "filter_common.h"
#include <atomic>
#include <vector>
#include <algorithm>

namespace flow {

class PortMatcher {
public:

    struct Rule {
        uint16_t begin;
        uint16_t end;
        RuleId   ruleId;
    };

    PortMatcher();
    ~PortMatcher();

    PortMatcher(const PortMatcher&) = delete;
    PortMatcher& operator=(const PortMatcher&) = delete;

    /// lock-free read path
    std::vector<RuleId> match(uint16_t port) const;

    /// rebuild lookup table (writer path)
    void rebuild(const std::vector<Rule>& rules);

private:
    struct LUT;

    // =======================
    // EBR infrastructure
    // =======================

    struct ThreadRecord {
        std::atomic<uint64_t> epoch{0};
        std::atomic<bool>     active{false};
        ThreadRecord*         next{nullptr};
    };

    struct RetiredLUT {
        LUT* ptr;
        uint64_t    retired_epoch;
    };

    void enter_epoch() const noexcept;
    void exit_epoch() const noexcept;
    void register_thread() const;
    void retire_lut(LUT* lut, uint64_t epoch);
    void try_reclaim();

    // =======================
    // LUT
    // =======================

    struct LUT {
        struct RuleList {
            RuleId* data{nullptr};
            uint32_t size{0};
        };

        RuleList ports[65536];
    };

    LUT* build_lut(const std::vector<Rule>& rules);

private:
    // active LUT
    std::atomic<LUT*> active_{nullptr};

    // EBR domain (per-instance!)
    mutable std::atomic<uint64_t> global_epoch_{1};
    mutable std::atomic<ThreadRecord*> thread_list_{nullptr};
    mutable std::vector<RetiredLUT> retired_;

    static constexpr size_t kMaxRetired = 8192;

    // TLS (still thread_local, but per-instance record)
    static thread_local ThreadRecord* tls_record_;
};

} // namespace flow