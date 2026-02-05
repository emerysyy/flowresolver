#include "domain_matcher.h"
#include <algorithm>
#include <cctype>

namespace flow {

size_t DomainMatcher::StringHash::operator()(std::string_view sv) const noexcept
{
    return std::hash<std::string_view>{}(sv);
}

size_t DomainMatcher::StringHash::operator()(const std::string& s) const noexcept
{
    return std::hash<std::string>{}(s);
}

bool DomainMatcher::StringEqual::operator()(std::string_view a, std::string_view b) const noexcept
{
    return a == b;
}

bool DomainMatcher::StringEqual::operator()(const std::string& a, const std::string& b) const noexcept
{
    return a == b;
}

bool DomainMatcher::StringEqual::operator()(const std::string& a, std::string_view b) const noexcept
{
    return a == b;
}

bool DomainMatcher::StringEqual::operator()(std::string_view a, const std::string& b) const noexcept
{
    return a == b;
}

DomainMatcher::DomainMatcher()
{
    root_ = std::make_unique<TrieNode>();
}

bool DomainMatcher::addRule(const DomainRule& rule)
{
    std::unique_lock lock(mutex_);

    if (!validateRulePattern(rule.pattern))
        return false;

    if (rule_index_.count(rule.rule_id))
        return false;

    std::string normalized = rule.pattern;
    normalizeInPlace(normalized);

    bool is_wildcard = false;
    std::string_view body;

    if (normalized == "*")
    {
        is_wildcard = true;
        body = std::string_view{};
    }
    else if (normalized.size() >= 2 && normalized[0] == '*' && normalized[1] == '.')
    {
        is_wildcard = true;
        body = std::string_view(normalized).substr(2);
    }
    else
    {
        body = normalized;
    }

    std::array<std::string_view, 16> labels;
    size_t count = 0;

    if (!body.empty())
    {
        count = splitReverseInPlace(body, labels);
        if (count == 0)
            return false;
    }

    std::vector<uint32_t> label_ids;
    label_ids.reserve(count);

    for (size_t i = 0; i < count; ++i)
    {
        std::string label_str(labels[i]);
        auto it = label_to_id_.find(label_str);
        if (it == label_to_id_.end())
        {
            uint32_t id = static_cast<uint32_t>(id_to_label_.size());
            label_to_id_.emplace(label_str, id);
            id_to_label_.push_back(std::move(label_str));
            label_ids.push_back(id);
        }
        else
        {
            label_ids.push_back(it->second);
        }
    }

    TrieNode* node = root_.get();
    for (uint32_t id : label_ids)
    {
        auto it = node->children.find(id);
        if (it == node->children.end())
            it = node->children.emplace(id, std::make_unique<TrieNode>()).first;
        node = it->second.get();
    }

    if (is_wildcard)
        node->wildcard_rule = rule.rule_id;
    else
        node->exact_rule = rule.rule_id;

    rule_index_.emplace(rule.rule_id, RuleIndex{label_ids, is_wildcard});
    return true;
}

std::vector<RuleId> DomainMatcher::match(std::string_view domain) const
{
    return matchAll(domain);
}

std::vector<RuleId> DomainMatcher::matchAll(std::string_view domain) const
{
    std::shared_lock lock(mutex_);

    if (!validateDomain(domain))
        return {};

    std::string normalized(domain);
    normalizeInPlace(normalized);

    std::array<std::string_view, 16> labels;
    size_t total_count = splitReverseInPlace(normalized, labels);
    if (total_count == 0)
        return {};

    std::array<uint32_t, 16> label_ids;
    size_t valid_count = 0;

    for (size_t i = 0; i < total_count; ++i)
    {
        std::string label_str(labels[i]);
        auto it = label_to_id_.find(label_str);
        if (it == label_to_id_.end())
        {
            valid_count = i;
            break;
        }
        label_ids[i] = it->second;
    }

    if (valid_count == 0)
        valid_count = total_count;

    std::vector<RuleId> results;
    matchAllRecursive(root_.get(), label_ids, valid_count, total_count, 0, results);

    return results;
}

void DomainMatcher::matchAllRecursive(const TrieNode* node, const std::array<uint32_t, 16>& label_ids, size_t valid_count, size_t total_count, size_t index, std::vector<RuleId>& results) const
{
    if (!node)
        return;

    if (index < valid_count)
    {
        auto it = node->children.find(label_ids[index]);
        if (it != node->children.end())
        {
            matchAllRecursive(it->second.get(), label_ids, valid_count, total_count, index + 1, results);
        }
    }

    if (index == valid_count && valid_count == total_count && node->exact_rule)
    {
        results.push_back(*node->exact_rule);
    }

    if (index < total_count && node->wildcard_rule)
    {
        results.push_back(*node->wildcard_rule);
    }
}

bool DomainMatcher::removeRule(RuleId rule_id)
{
    std::unique_lock lock(mutex_);

    auto it = rule_index_.find(rule_id);
    if (it == rule_index_.end())
        return false;

    removeRuleRecursive(root_.get(), it->second.labels, 0, it->second.is_wildcard);

    rule_index_.erase(it);
    return true;
}

bool DomainMatcher::removeRuleRecursive(TrieNode* node, const std::vector<uint32_t>& labels, size_t index, bool is_wildcard)
{
    if (!node)
        return false;

    if (index == labels.size())
    {
        if (is_wildcard)
            node->wildcard_rule.reset();
        else
            node->exact_rule.reset();
    }
    else
    {
        auto it = node->children.find(labels[index]);
        if (it == node->children.end())
            return false;

        bool should_erase = removeRuleRecursive(it->second.get(), labels, index + 1, is_wildcard);

        if (should_erase)
            node->children.erase(it);
    }

    return node->children.empty() && !node->exact_rule && !node->wildcard_rule;
}

void DomainMatcher::clear()
{
    std::unique_lock lock(mutex_);
    root_ = std::make_unique<TrieNode>();
    rule_index_.clear();
    label_to_id_.clear();
    id_to_label_.clear();
}

bool DomainMatcher::validateDomain(std::string_view d)
{
    if (d.empty())
        return false;
    if (d.front() == '.' || d.back() == '.')
        return false;
    if (d.find("..") != std::string_view::npos)
        return false;
    return true;
}

bool DomainMatcher::validateRulePattern(const std::string& s)
{
    if (s.empty())
        return false;

    if (s == "*")
        return true;

    if (s.front() == '.' || s.back() == '.')
        return false;

    if (s.find("..") != std::string::npos)
        return false;

    if (s[0] == '*')
    {
        if (s.size() < 3 || s[1] != '.')
            return false;
        if (s.find('*', 1) != std::string::npos)
            return false;
    }
    else if (s.find('*') != std::string::npos)
    {
        return false;
    }

    return true;
}

void DomainMatcher::normalizeInPlace(std::string& s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    while (!s.empty() && s.back() == '.')
        s.pop_back();
}

size_t DomainMatcher::splitReverseInPlace(std::string_view domain, std::array<std::string_view, 16>& labels)
{
    size_t count = 0;
    size_t end = domain.size();

    while (end > 0)
    {
        if (count >= labels.size())
            return 0;

        size_t dot = domain.rfind('.', end - 1);
        if (dot == std::string_view::npos)
        {
            auto part = domain.substr(0, end);
            if (part.empty())
                return 0;
            labels[count++] = part;
            break;
        }

        auto part = domain.substr(dot + 1, end - dot - 1);
        if (part.empty())
            return 0;

        labels[count++] = part;
        end = dot;
    }

    return count;
}

} // namespace flow