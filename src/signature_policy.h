#pragma once
#include <string_view>

namespace stoker::plugin::signature
{
    enum class TrustPolicy { Forward, AcceptMatched, AcceptAll };
    inline bool ParsePolicy(std::string_view value, TrustPolicy& policy)
    {
        if (value == "forward") policy = TrustPolicy::Forward;
        else if (value == "accept-matched") policy = TrustPolicy::AcceptMatched;
        else if (value == "accept-all") policy = TrustPolicy::AcceptAll;
        else return false;
        return true;
    }

    template<class Char> size_t FilenameStart(std::basic_string_view<Char> path)
    {
        size_t start = 0;
        for (size_t i = 0; i < path.size(); ++i)
            if (path[i] == Char('/') || path[i] == Char('\\')) start = i + 1;
        // C:a.dll is drive-relative, but still has a directory prefix to preserve.
        if (!start && path.size() >= 2 && path[1] == Char(':')) start = 2;
        return start;
    }

    template<class Char> bool Matches(std::basic_string_view<Char> path, std::basic_string_view<Char> filename)
    {
        path.remove_prefix(FilenameStart(path));
        if (path.size() != filename.size()) return false;
        auto fold = [](Char c) { return c >= Char('A') && c <= Char('Z') ? Char(c + ('a' - 'A')) : c; };
        for (size_t i = 0; i < path.size(); ++i) if (fold(path[i]) != fold(filename[i])) return false;
        return true;
    }
}
