#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include "addrman.h"
#include <string>
#include "netbase.h"

#include <vector>
#include "protocol.h"
#include "utilstrencodings.h"

#define NODE_NONE 0

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
    CNetAddr addr;
    LookupHost(ip, addr, false);
    return addr;
}

static CSubNet ResolveSubNet(const std::string& subnet)
{
    CSubNet ret;
    LookupSubNet(subnet, ret);
    return ret;
}

static CNetAddr CreateInternal(const char* host)
{
    CNetAddr addr;
    addr.SetInternal(host);
    return addr;
}

namespace TestNetBaseTests {

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

    TEST(TestNetBaseTests, subnet_test) {
        EXPECT_TRUE(ResolveSubNet("1.2.3.0/24") == ResolveSubNet("1.2.3.0/255.255.255.0"));
        EXPECT_TRUE(ResolveSubNet("1.2.3.0/24") != ResolveSubNet("1.2.4.0/255.255.255.0"));
        EXPECT_TRUE(ResolveSubNet("1.2.3.0/24").Match(ResolveIP("1.2.3.4")));
        EXPECT_TRUE(!ResolveSubNet("1.2.2.0/24").Match(ResolveIP("1.2.3.4")));
        EXPECT_TRUE(ResolveSubNet("1.2.3.4").Match(ResolveIP("1.2.3.4")));
        EXPECT_TRUE(ResolveSubNet("1.2.3.4/32").Match(ResolveIP("1.2.3.4")));
        EXPECT_TRUE(!ResolveSubNet("1.2.3.4").Match(ResolveIP("5.6.7.8")));
        EXPECT_TRUE(!ResolveSubNet("1.2.3.4/32").Match(ResolveIP("5.6.7.8")));
        EXPECT_TRUE(ResolveSubNet("::ffff:127.0.0.1").Match(ResolveIP("127.0.0.1")));
        EXPECT_TRUE(ResolveSubNet("1:2:3:4:5:6:7:8").Match(ResolveIP("1:2:3:4:5:6:7:8")));
        EXPECT_TRUE(!ResolveSubNet("1:2:3:4:5:6:7:8").Match(ResolveIP("1:2:3:4:5:6:7:9")));
        EXPECT_TRUE(ResolveSubNet("1:2:3:4:5:6:7:0/112").Match(ResolveIP("1:2:3:4:5:6:7:1234")));
        EXPECT_TRUE(ResolveSubNet("192.168.0.1/24").Match(ResolveIP("192.168.0.2")));
        EXPECT_TRUE(ResolveSubNet("192.168.0.20/29").Match(ResolveIP("192.168.0.18")));
        EXPECT_TRUE(ResolveSubNet("1.2.2.1/24").Match(ResolveIP("1.2.2.4")));
        EXPECT_TRUE(ResolveSubNet("1.2.2.110/31").Match(ResolveIP("1.2.2.111")));
        EXPECT_TRUE(ResolveSubNet("1.2.2.20/26").Match(ResolveIP("1.2.2.63")));
        // All-Matching IPv6 Matches arbitrary IPv6
        EXPECT_TRUE(ResolveSubNet("::/0").Match(ResolveIP("1:2:3:4:5:6:7:1234")));
        // But not `::` or `0.0.0.0` because they are considered invalid addresses
        EXPECT_TRUE(!ResolveSubNet("::/0").Match(ResolveIP("::")));
        EXPECT_TRUE(!ResolveSubNet("::/0").Match(ResolveIP("0.0.0.0")));
        // Addresses from one network (IPv4) don't belong to subnets of another network (IPv6)
        EXPECT_TRUE(!ResolveSubNet("::/0").Match(ResolveIP("1.2.3.4")));
        // All-Matching IPv4 does not Match IPv6
        EXPECT_TRUE(!ResolveSubNet("0.0.0.0/0").Match(ResolveIP("1:2:3:4:5:6:7:1234")));
        // Invalid subnets Match nothing (not even invalid addresses)
        EXPECT_TRUE(!CSubNet().Match(ResolveIP("1.2.3.4")));
        EXPECT_TRUE(!ResolveSubNet("").Match(ResolveIP("4.5.6.7")));
        EXPECT_TRUE(!ResolveSubNet("bloop").Match(ResolveIP("0.0.0.0")));
        EXPECT_TRUE(!ResolveSubNet("bloop").Match(ResolveIP("hab")));
        // Check valid/invalid
        EXPECT_TRUE(ResolveSubNet("1.2.3.0/0").IsValid());
        EXPECT_TRUE(!ResolveSubNet("1.2.3.0/-1").IsValid());
        EXPECT_TRUE(ResolveSubNet("1.2.3.0/32").IsValid());
        EXPECT_TRUE(!ResolveSubNet("1.2.3.0/33").IsValid());
        EXPECT_TRUE(!ResolveSubNet("1.2.3.0/300").IsValid());
        EXPECT_TRUE(ResolveSubNet("1:2:3:4:5:6:7:8/0").IsValid());
        EXPECT_TRUE(ResolveSubNet("1:2:3:4:5:6:7:8/33").IsValid());
        EXPECT_TRUE(!ResolveSubNet("1:2:3:4:5:6:7:8/-1").IsValid());
        EXPECT_TRUE(ResolveSubNet("1:2:3:4:5:6:7:8/128").IsValid());
        EXPECT_TRUE(!ResolveSubNet("1:2:3:4:5:6:7:8/129").IsValid());
        EXPECT_TRUE(!ResolveSubNet("fuzzy").IsValid());

        //CNetAddr constructor test
        EXPECT_TRUE(CSubNet(ResolveIP("127.0.0.1")).IsValid());
        EXPECT_TRUE(CSubNet(ResolveIP("127.0.0.1")).Match(ResolveIP("127.0.0.1")));
        EXPECT_TRUE(!CSubNet(ResolveIP("127.0.0.1")).Match(ResolveIP("127.0.0.2")));
        EXPECT_TRUE(CSubNet(ResolveIP("127.0.0.1")).ToString() == "127.0.0.1/32");

        CSubNet subnet = CSubNet(ResolveIP("1.2.3.4"), 32);
        EXPECT_EQ(subnet.ToString(), "1.2.3.4/32");
        subnet = CSubNet(ResolveIP("1.2.3.4"), 8);
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/8");
        subnet = CSubNet(ResolveIP("1.2.3.4"), 0);
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/0");

        subnet = CSubNet(ResolveIP("1.2.3.4"), ResolveIP("255.255.255.255"));
        EXPECT_EQ(subnet.ToString(), "1.2.3.4/32");
        subnet = CSubNet(ResolveIP("1.2.3.4"), ResolveIP("255.0.0.0"));
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/8");
        subnet = CSubNet(ResolveIP("1.2.3.4"), ResolveIP("0.0.0.0"));
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/0");

        EXPECT_TRUE(CSubNet(ResolveIP("1:2:3:4:5:6:7:8")).IsValid());
        EXPECT_TRUE(CSubNet(ResolveIP("1:2:3:4:5:6:7:8")).Match(ResolveIP("1:2:3:4:5:6:7:8")));
        EXPECT_TRUE(!CSubNet(ResolveIP("1:2:3:4:5:6:7:8")).Match(ResolveIP("1:2:3:4:5:6:7:9")));
        EXPECT_TRUE(CSubNet(ResolveIP("1:2:3:4:5:6:7:8")).ToString() == "1:2:3:4:5:6:7:8/128");
        // IPv4 address with IPv6 netmask or the other way around.
        EXPECT_TRUE(!CSubNet(ResolveIP("1.1.1.1"), ResolveIP("ffff::")).IsValid());
        EXPECT_TRUE(!CSubNet(ResolveIP("::1"), ResolveIP("255.0.0.0")).IsValid());
        // Can't subnet TOR (or any other non-IPv4 and non-IPv6 network).
        EXPECT_TRUE(!CSubNet(ResolveIP("5wyqrzbvrdsumnok.onion"), ResolveIP("255.0.0.0")).IsValid());

        subnet = ResolveSubNet("1.2.3.4/255.255.255.255");
        EXPECT_EQ(subnet.ToString(), "1.2.3.4/32");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.254");
        EXPECT_EQ(subnet.ToString(), "1.2.3.4/31");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.252");
        EXPECT_EQ(subnet.ToString(), "1.2.3.4/30");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.248");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/29");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.240");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/28");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.224");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/27");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.192");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/26");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.128");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/25");
        subnet = ResolveSubNet("1.2.3.4/255.255.255.0");
        EXPECT_EQ(subnet.ToString(), "1.2.3.0/24");
        subnet = ResolveSubNet("1.2.3.4/255.255.254.0");
        EXPECT_EQ(subnet.ToString(), "1.2.2.0/23");
        subnet = ResolveSubNet("1.2.3.4/255.255.252.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/22");
        subnet = ResolveSubNet("1.2.3.4/255.255.248.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/21");
        subnet = ResolveSubNet("1.2.3.4/255.255.240.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/20");
        subnet = ResolveSubNet("1.2.3.4/255.255.224.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/19");
        subnet = ResolveSubNet("1.2.3.4/255.255.192.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/18");
        subnet = ResolveSubNet("1.2.3.4/255.255.128.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/17");
        subnet = ResolveSubNet("1.2.3.4/255.255.0.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/16");
        subnet = ResolveSubNet("1.2.3.4/255.254.0.0");
        EXPECT_EQ(subnet.ToString(), "1.2.0.0/15");
        subnet = ResolveSubNet("1.2.3.4/255.252.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/14");
        subnet = ResolveSubNet("1.2.3.4/255.248.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/13");
        subnet = ResolveSubNet("1.2.3.4/255.240.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/12");
        subnet = ResolveSubNet("1.2.3.4/255.224.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/11");
        subnet = ResolveSubNet("1.2.3.4/255.192.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/10");
        subnet = ResolveSubNet("1.2.3.4/255.128.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/9");
        subnet = ResolveSubNet("1.2.3.4/255.0.0.0");
        EXPECT_EQ(subnet.ToString(), "1.0.0.0/8");
        subnet = ResolveSubNet("1.2.3.4/254.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/7");
        subnet = ResolveSubNet("1.2.3.4/252.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/6");
        subnet = ResolveSubNet("1.2.3.4/248.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/5");
        subnet = ResolveSubNet("1.2.3.4/240.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/4");
        subnet = ResolveSubNet("1.2.3.4/224.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/3");
        subnet = ResolveSubNet("1.2.3.4/192.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/2");
        subnet = ResolveSubNet("1.2.3.4/128.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/1");
        subnet = ResolveSubNet("1.2.3.4/0.0.0.0");
        EXPECT_EQ(subnet.ToString(), "0.0.0.0/0");

        subnet = ResolveSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        EXPECT_EQ(subnet.ToString(), "1:2:3:4:5:6:7:8/128");
        subnet = ResolveSubNet("1:2:3:4:5:6:7:8/ffff:0000:0000:0000:0000:0000:0000:0000");
        EXPECT_EQ(subnet.ToString(), "1::/16");
        subnet = ResolveSubNet("1:2:3:4:5:6:7:8/0000:0000:0000:0000:0000:0000:0000:0000");
        EXPECT_EQ(subnet.ToString(), "::/0");
        // Invalid netmasks (with 1-bits after 0-bits)
        subnet = ResolveSubNet("1.2.3.4/255.255.232.0");
        EXPECT_TRUE(!subnet.IsValid());
        subnet = ResolveSubNet("1.2.3.4/255.0.255.255");
        EXPECT_TRUE(!subnet.IsValid());
        subnet = ResolveSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ff0f");
        EXPECT_TRUE(!subnet.IsValid());

    }

    TEST(TestNetBaseTests, netbase_getgroup) {

        std::vector<bool> asmap; // use /16
        EXPECT_TRUE(ResolveIP("127.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // Local -> !Routable()
        EXPECT_TRUE(ResolveIP("257.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // !Valid -> !Routable()
        EXPECT_TRUE(ResolveIP("10.0.0.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // RFC1918 -> !Routable()
        EXPECT_TRUE(ResolveIP("169.254.1.1").GetGroup(asmap) == std::vector<unsigned char>({0})); // RFC3927 -> !Routable()
        EXPECT_TRUE(ResolveIP("1.2.3.4").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // IPv4
        EXPECT_TRUE(ResolveIP("::FFFF:0:102:304").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC6145
        EXPECT_TRUE(ResolveIP("64:FF9B::102:304").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC6052
        EXPECT_TRUE(ResolveIP("2002:102:304:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC3964
        EXPECT_TRUE(ResolveIP("2001:0:9999:9999:9999:9999:FEFD:FCFB").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV4, 1, 2})); // RFC4380
        EXPECT_TRUE(ResolveIP("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_ONION, 239})); // Tor
        EXPECT_TRUE(ResolveIP("2001:470:abcd:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV6, 32, 1, 4, 112, 175})); //he.net
        EXPECT_TRUE(ResolveIP("2001:2001:9999:9999:9999:9999:9999:9999").GetGroup(asmap) == std::vector<unsigned char>({(unsigned char)NET_IPV6, 32, 1, 32, 1})); //IPv6

        // baz.net sha256 hash: 12929400eb4607c4ac075f087167e75286b179c693eb059a01774b864e8fe505
        std::vector<unsigned char> internal_group = {NET_INTERNAL, 0x12, 0x92, 0x94, 0x00, 0xeb, 0x46, 0x07, 0xc4, 0xac, 0x07};
        EXPECT_TRUE(CreateInternal("baz.net").GetGroup(asmap) == internal_group);

        // dummy "ip" for this association with a prefix of fd6b:88c0:8724::/48 (fd + sha256(bitcoin)[0:5])
        std::vector<unsigned char> internal_group_test = {NET_INTERNAL, 0x18, 0x75, 0x13, 0xd6, 0x8a, 0x23, 0x70, 0xfd, 0x4a, 0x5d};
        CNetAddr dummyAddr = CreateInternal("decker.dummy");
        EXPECT_TRUE(dummyAddr.GetGroup(asmap) == internal_group_test);
        EXPECT_EQ(std::string("db2rhvukenyp2ss5.internal"), dummyAddr.ToStringIP());
    }

    static const std::vector<CAddress> fixture_addresses({
        CAddress(
            CService(CNetAddr(in6addr_loopback), 0 /* port */),
            NODE_NONE,
            0x4966bc61U /* Fri Jan  9 02:54:25 UTC 2009 */
        ),
        CAddress(
            CService(CNetAddr(in6addr_loopback), 0x00f1 /* port */),
            NODE_NETWORK,
            0x83766279U /* Tue Nov 22 11:22:33 UTC 2039 */
        ),
        CAddress(
            CService(CNetAddr(in6addr_loopback), 0xf1f2 /* port */),
            NODE_NETWORK,
            0xffffffffU /* Sun Feb  7 06:28:15 UTC 2106 */
        )
    });

    // fixture_addresses should equal to this when serialized in V1 format.
    // When this is unserialized from V1 format it should equal to fixture_addresses.
    static constexpr const char* stream_addrv1_hex =
        "03" // number of entries

        "61bc6649"                         // time, Fri Jan  9 02:54:25 UTC 2009
        "0000000000000000"                 // service flags, NODE_NONE
        "00000000000000000000000000000001" // address, fixed 16 bytes (IPv4 embedded in IPv6)
        "0000"                             // port

        "79627683"                         // time, Tue Nov 22 11:22:33 UTC 2039
        "0100000000000000"                 // service flags, NODE_NETWORK
        "00000000000000000000000000000001" // address, fixed 16 bytes (IPv6)
        "00f1"                             // port

        "ffffffff"                         // time, Sun Feb  7 06:28:15 UTC 2106
        "0100000000000000"                 // service flags, service flags, NODE_NETWORK
        "00000000000000000000000000000001" // address, fixed 16 bytes (IPv6)
        "f1f2";                            // port

    // fixture_addresses should equal to this when serialized in V2 format.
    // When this is unserialized from V2 format it should equal to fixture_addresses.
    static constexpr const char* stream_addrv2_hex =
        "03" // number of entries

        "61bc6649"                         // time, Fri Jan  9 02:54:25 UTC 2009
        "00"                               // service flags, COMPACTSIZE(NODE_NONE)
        "02"                               // network id, IPv6
        "10"                               // address length, COMPACTSIZE(16)
        "00000000000000000000000000000001" // address
        "0000"                             // port

        "79627683"                         // time, Tue Nov 22 11:22:33 UTC 2039
        "01"                               // service flags, COMPACTSIZE(NODE_NETWORK)
        "02"                               // network id, IPv6
        "10"                               // address length, COMPACTSIZE(16)
        "00000000000000000000000000000001" // address
        "00f1"                             // port

        "ffffffff"                         // time, Sun Feb  7 06:28:15 UTC 2106
        "01"                               // service flags, COMPACTSIZE(NODE_NETWORK)
        "02"                               // network id, IPv6
        "10"                               // address length, COMPACTSIZE(16)
        "00000000000000000000000000000001" // address
        "f1f2";                            // port

    TEST(TestNetBaseTests, caddress_serialize_v1) {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

        s << fixture_addresses;
        EXPECT_EQ(HexStr(s), stream_addrv1_hex);
    }

    TEST(TestNetBaseTests, caddress_unserialize_v1) {
        /* CDataStream(const std::vector<unsigned char>& vchIn, int nTypeIn, int nVersionIn) ... construct stream from pre-defined vector */
        CDataStream s(ParseHex(stream_addrv1_hex), SER_NETWORK, PROTOCOL_VERSION);
        std::vector<CAddress> addresses_unserialized;

        s >> addresses_unserialized;
        EXPECT_TRUE(fixture_addresses == addresses_unserialized);
    }

    TEST(TestNetBaseTests, caddress_serialize_v2)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);

        s << fixture_addresses;
        EXPECT_EQ(HexStr(s), stream_addrv2_hex);
    }

    TEST(TestNetBaseTests, caddress_unserialize_v2)
    {
        CDataStream s(ParseHex(stream_addrv2_hex), SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
        std::vector<CAddress> addresses_unserialized;

        s >> addresses_unserialized;
        EXPECT_TRUE(fixture_addresses == addresses_unserialized);
    }
}
