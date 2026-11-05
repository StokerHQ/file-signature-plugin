#include "../src/signature_policy.h"
#include <cassert>
#include <cstdio>
using namespace stoker::plugin::signature;
int main()
{
    assert(Matches<char>("dir/VeNdOr_Loader64.DLL", "vendor_loader64.dll"));
    assert(Matches<char16_t>(u"C:\\Ä\\a.dll", u"A.DLL"));
    assert(Matches<char>("C:a.dll", "a.dll"));
    assert(!Matches<char>("a.dll.bak", "a.dll"));
    assert(!Matches<char>("a.dll/other", "a.dll"));
    assert(!Matches<char>("dir/", "a.dll"));
    assert(FilenameStart<char>("C:a.dll") == 2);
    assert(FilenameStart<char>("\\\\server\\share\\a.dll") == 15);
    TrustPolicy policy;
    assert(ParsePolicy("forward", policy) && policy == TrustPolicy::Forward);
    assert(ParsePolicy("accept-matched", policy) && policy == TrustPolicy::AcceptMatched);
    assert(ParsePolicy("accept-all", policy) && policy == TrustPolicy::AcceptAll);
    assert(!ParsePolicy("unknown", policy));
    puts("Portable file signature policy tests passed.");
}
