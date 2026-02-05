#pragma once

#include "filter_common.h"
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <array>
#include <optional>
#include <shared_mutex>

namespace flow {

struct DomainRule
{
    RuleId rule_id;
    std::string pattern;
};

/* =========================
 * DomainMatcher
 * ========================= */
class DomainMatcher
{
public:
    DomainMatcher();
    ~DomainMatcher() = default;

    bool addRule(const DomainRule& rule);
    bool removeRule(RuleId rule_id);
    void clear();

    std::vector<RuleId> match(std::string_view domain) const;
    std::vector<RuleId> matchAll(std::string_view domain) const;

private:
    struct TrieNode
    {
        std::unordered_map<uint32_t, std::unique_ptr<TrieNode>> children;
        std::optional<RuleId> exact_rule;
        std::optional<RuleId> wildcard_rule;
    };

    struct RuleIndex
    {
        std::vector<uint32_t> labels;
        bool is_wildcard;
    };

    /* ===== Hash / Equal (C++20 heterogeneous lookup) ===== */
    struct StringHash
    {
        using is_transparent = void;
        size_t operator()(std::string_view sv) const noexcept;
        size_t operator()(const std::string& s) const noexcept;
    };

    struct StringEqual
    {
        using is_transparent = void;
        bool operator()(std::string_view a, std::string_view b) const noexcept;
        bool operator()(const std::string& a, const std::string& b) const noexcept;
        bool operator()(const std::string& a, std::string_view b) const noexcept;
        bool operator()(std::string_view a, const std::string& b) const noexcept;
    };

private:
    void matchAllRecursive(
        const TrieNode* node,
        const std::array<uint32_t, 16>& label_ids,
        size_t count,
        size_t index,
        std::vector<RuleId>& results) const;

    bool removeRuleRecursive(
        TrieNode* node,
        const std::vector<uint32_t>& labels,
        size_t index,
        bool is_wildcard);

    static bool validateDomain(std::string_view domain);
    static bool validateRulePattern(const std::string& rule);
    static void normalizeInPlace(std::string& s);

    static size_t splitReverseInPlace(
        std::string_view domain,
        std::array<std::string_view, 16>& labels);

private:
    std::unique_ptr<TrieNode> root_;

    std::unordered_map<uint64_t, RuleIndex> rule_index_;

    std::unordered_map<
        std::string,
        uint32_t,
        StringHash,
        StringEqual> label_to_id_;

    std::vector<std::string> id_to_label_;

    mutable std::shared_mutex mutex_;
};

} // namespace flow