#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include "addrman.h"
#include <string>
#include "netbase.h"

#define GTEST_COUT_NOCOLOR std::cerr << "[          ] [ INFO ] "
/*
namespace testing
{
    namespace internal
    {
    enum GTestColor {
        COLOR_DEFAULT,
        COLOR_RED,
        COLOR_GREEN,
        COLOR_YELLOW
    };

    extern void ColoredPrintf(GTestColor color, const char* fmt, ...);
    }
}
#define PRINTF(...)  do { testing::internal::ColoredPrintf(testing::internal::COLOR_GREEN, "[          ] "); testing::internal::ColoredPrintf(testing::internal::COLOR_YELLOW, __VA_ARGS__); } while(0)
*/

// https://stackoverflow.com/questions/63464085/coloredprintf-in-recent-googletest
#define PRINTF(...)  do { std::cerr << "[          ] "; std::cerr << strprintf(__VA_ARGS__); } while(0)

// C++ stream interface
class TestCout : public std::stringstream
{
    public:
        ~TestCout()
        {
            PRINTF("%s",str().c_str());
        }
};

#define GTEST_COUT_COLOR TestCout()

using namespace std;

static CNetAddr ResolveIP(const std::string& ip)
{
        vector<CNetAddr> vIPs;
        CNetAddr addr;
        if (LookupHost(ip.c_str(), vIPs)) {
                addr = vIPs[0];
        } else
        {
            // it was BOOST_CHECK_MESSAGE, but we can't use ASSERT outside a test
            GTEST_COUT_COLOR << strprintf("failed to resolve: %s", ip) << std::endl;
        }
        return addr;
}

static CNetAddr CreateInternal(const char* host)
{
    CNetAddr addr;
    addr.SetInternal(host);
    return addr;
}

namespace TestNetBaseTests {

    TEST(TestNetBaseTests, netbase_getgroup) {

        std::vector<bool> asmap; // use /16
        ASSERT_TRUE(ResolveIP("127.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // Local -> !Routable()
        ASSERT_TRUE(ResolveIP("257.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // !Valid -> !Routable()
        ASSERT_TRUE(ResolveIP("10.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // RFC1918 -> !Routable()
        ASSERT_TRUE(ResolveIP("169.254.1.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // RFC3927 -> !Routable()
        ASSERT_TRUE(ResolveIP("1.2.3.4").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // IPv4

        // std::vector<unsigned char> vch = ResolveIP("4.3.2.1").GetGroup(asmap);
        // GTEST_COUT_COLOR << boost::to_string((int)vch[0]) << boost::to_string((int)vch[1]) << boost::to_string((int)vch[2]) << std::endl;

        ASSERT_TRUE(ResolveIP("::FFFF:0:102:304").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC6145
        ASSERT_TRUE(ResolveIP("64:FF9B::102:304").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC6052
        ASSERT_TRUE(ResolveIP("2002:102:304:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC3964
        ASSERT_TRUE(ResolveIP("2001:0:9999:9999:9999:9999:FEFD:FCFB").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC4380
        ASSERT_TRUE(ResolveIP("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_ONION, 239})); // Tor
        ASSERT_TRUE(ResolveIP("2001:470:abcd:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV6, 32, 1, 4, 112, 175})); //he.net
        ASSERT_TRUE(ResolveIP("2001:2001:9999:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV6, 32, 1, 32, 1})); //IPv6

        // baz.net sha256 hash: 12929400eb4607c4ac075f087167e75286b179c693eb059a01774b864e8fe505
        std::vector<unsigned char> internal_group = {NET_INTERNAL, 0x12, 0x92, 0x94, 0x00, 0xeb, 0x46, 0x07, 0xc4, 0xac, 0x07};
        EXPECT_TRUE(CreateInternal("baz.net").GetGroup(asmap) == internal_group);

        // dummy "ip" for this association with a prefix of fd6b:88c0:8724::/48 (fd + sha256(bitcoin)[0:5])
        std::vector<unsigned char> internal_group_test = {NET_INTERNAL, 0x18, 0x75, 0x13, 0xd6, 0x8a, 0x23, 0x70, 0xfd, 0x4a, 0x5d};
        CNetAddr dummyAddr = CreateInternal("decker.dummy");
        EXPECT_TRUE(dummyAddr.GetGroup(asmap) == internal_group_test);
        EXPECT_EQ(std::string("db2rhvukenyp2ss5.internal"), dummyAddr.ToStringIP());
    }

    TEST(TestNetBaseTests, netbase_networks) {

        EXPECT_TRUE(ResolveIP("127.0.0.1").GetNetwork()                              == NET_UNROUTABLE);
        EXPECT_TRUE(ResolveIP("::1").GetNetwork()                                    == NET_UNROUTABLE);
        EXPECT_TRUE(ResolveIP("8.8.8.8").GetNetwork()                                == NET_IPV4);
        EXPECT_TRUE(ResolveIP("2001::8888").GetNetwork()                             == NET_IPV6);
        EXPECT_TRUE(ResolveIP("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").GetNetwork() == NET_ONION);
        EXPECT_TRUE(CreateInternal("foo.com").GetNetwork()                           == NET_INTERNAL);

    }

    TEST(TestNetBaseTests, netbase_properties) {
        EXPECT_TRUE(CNetAddr("127.0.0.1").IsIPv4());
        EXPECT_TRUE(CNetAddr("::FFFF:192.168.1.1").IsIPv4());
        EXPECT_TRUE(CNetAddr("::1").IsIPv6());
        EXPECT_TRUE(CNetAddr("10.0.0.1").IsRFC1918());
        EXPECT_TRUE(CNetAddr("192.168.1.1").IsRFC1918());
        EXPECT_TRUE(CNetAddr("172.31.255.255").IsRFC1918());
        EXPECT_TRUE(CNetAddr("2001:0DB8::").IsRFC3849());
        EXPECT_TRUE(CNetAddr("169.254.1.1").IsRFC3927());
        EXPECT_TRUE(CNetAddr("2002::1").IsRFC3964());
        EXPECT_TRUE(CNetAddr("FC00::").IsRFC4193());
        EXPECT_TRUE(CNetAddr("2001::2").IsRFC4380());
        EXPECT_TRUE(CNetAddr("2001:10::").IsRFC4843());
        EXPECT_TRUE(CNetAddr("FE80::").IsRFC4862());
        EXPECT_TRUE(CNetAddr("64:FF9B::").IsRFC6052());
        EXPECT_TRUE(CNetAddr("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").IsTor());
        EXPECT_TRUE(CNetAddr("127.0.0.1").IsLocal());
        EXPECT_TRUE(CNetAddr("::1").IsLocal());
        EXPECT_TRUE(CNetAddr("8.8.8.8").IsRoutable());
        EXPECT_TRUE(CNetAddr("2001::1").IsRoutable());
        EXPECT_TRUE(CNetAddr("127.0.0.1").IsValid());
        EXPECT_TRUE(CreateInternal("FD6B:88C0:8724:edb1:8e4:3588:e546:35ca").IsInternal());
        EXPECT_TRUE(CreateInternal("bar.com").IsInternal());
    }

    TEST(TestNetBaseTests, embedded_test) {
        CNetAddr addr1(ResolveIP("1.2.3.4"));
        CNetAddr addr2(ResolveIP("::FFFF:0102:0304"));
        EXPECT_TRUE(addr2.IsIPv4());
        EXPECT_EQ(addr1.ToString(), addr2.ToString());
    }
}
