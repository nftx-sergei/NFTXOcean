#include <gtest/gtest.h>
#include "sync.h"
#include "net.h"

#include <memory>
#include <utility>
#include <vector>

namespace TestNetTests {

    //! Substitute for C++14 std::make_unique.
    template <typename T, typename... Args>
    std::unique_ptr<T> MakeUnique(Args&&... args)
    {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

    class CChildCService : public CService {
        public:
            explicit CChildCService(const CService &ipIn) : CService(ipIn) {};
            uint32_t GetScopeId() { return m_scope_id; }
    };

    // https://github.com/bitcoin/bitcoin/pull/14728 - fix uninitialized read when stringifying an addrLocal
    // prior to commit containing this test, it triggers an undefined behavior
    TEST(TestNetTests, ipv4_peer_with_ipv6_addrMe_test) {
        // set up local addresses; all that's necessary to reproduce the bug is
        // that a normal IPv4 address is among the entries, but if this address is
        // !IsRoutable the undefined behavior is easier to trigger deterministically
        {
            LOCK(cs_mapLocalHost);
            in_addr ipv4AddrLocal;
            ipv4AddrLocal.s_addr = 0x0100007f;
            CNetAddr addr = CNetAddr(ipv4AddrLocal);
            LocalServiceInfo lsi;
            lsi.nScore = 23;
            lsi.nPort = 42;
            mapLocalHost[addr] = lsi;
        }

        // create a peer with an IPv4 address
        in_addr ipv4AddrPeer;
        ipv4AddrPeer.s_addr = 0xa0b0c001;
        CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
        // std::unique_ptr<CNode> pnode = MakeUnique<CNode>(0, NODE_NETWORK, 0, INVALID_SOCKET, addr, 0, 0, CAddress{}, std::string{}, false);
        std::unique_ptr<CNode> pnode = MakeUnique<CNode>(INVALID_SOCKET, addr, std::string{}, false);

        // pnode->fSuccessfullyConnected.store(true); // std::atomic_bool
        pnode->fSuccessfullyConnected = true;

        // the peer claims to be reaching us via IPv6
        in6_addr ipv6AddrLocal;
        memset(ipv6AddrLocal.s6_addr, 0, 16);
        ipv6AddrLocal.s6_addr[0] = 0xcc;

        CNetAddr cna_with_scope_set(ipv6AddrLocal, 0); // set scope to 0
        CAddress addrLocal = CAddress(CService(cna_with_scope_set, 7777), NODE_NETWORK);

        // pnode->SetAddrLocal(addrLocal);
        pnode->addrLocal = addrLocal;

        ASSERT_TRUE(pnode->vAddrToSend.size() == 0);

        // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
        AdvertizeLocal(&*pnode);

        /* AdvertizeLocal calls SetIP without setting the scopeId:

           AdvertizeLocal(CNode * pnode) -> GetLocalAddress(const CNetAddr * paddrPeer) -> GetLocal(CService & addr, const CNetAddr * paddrPeer),
           last proc took value from mapLocalHost which contains only IPv4 address we put earlier (127.0.0.1:42), constructed without
           set any scope (!) - CNetAddr(ipv4AddrLocal).
        */

        ASSERT_TRUE(pnode->vAddrToSend.size() == 1);

        CChildCService ccs(pnode->vAddrToSend.back());
        // scopeId should be initialized to 0, when fix applied
        ASSERT_TRUE(ccs.GetScopeId() == 0);

        // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
        ASSERT_TRUE(1);

    }

    TEST(TestNetTests, cnetaddr_basic) {

        CNetAddr addr;

        // IPv4, INADDR_ANY
        ASSERT_TRUE(LookupHost("0.0.0.0", addr, false));
        ASSERT_TRUE(!addr.IsValid());
        ASSERT_TRUE(addr.IsIPv4());

        EXPECT_TRUE(addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "0.0.0.0");

        // IPv4, INADDR_NONE
        ASSERT_TRUE(LookupHost("255.255.255.255", addr, false));
        ASSERT_TRUE(!addr.IsValid());
        ASSERT_TRUE(addr.IsIPv4());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "255.255.255.255");

        // IPv4, casual
        ASSERT_TRUE(LookupHost("12.34.56.78", addr, false));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv4());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "12.34.56.78");

        // IPv6, in6addr_any
        ASSERT_TRUE(LookupHost("::", addr, false));
        ASSERT_TRUE(!addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());

        EXPECT_TRUE(addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "::");

        // IPv6, casual
        ASSERT_TRUE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

        // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
        // We support non-negative decimal integers (uint32_t) as zone id indices.
        // Test with a fairly-high value, e.g. 32, to avoid locally reserved ids.
        const std::string link_local{"fe80::1"};
        const std::string scoped_addr{link_local + "%32"};
        ASSERT_TRUE(LookupHost(scoped_addr, addr, false));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());
        EXPECT_TRUE(!addr.IsBindAny());
        const std::string addr_str{addr.ToString()};
        EXPECT_TRUE(addr_str == scoped_addr || addr_str == "fe80:0:0:0:0:0:0:1");
        // The fallback case "fe80:0:0:0:0:0:0:1" is needed for macOS 10.14/10.15 and (probably) later.
        // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
        ASSERT_TRUE(LookupHost(link_local + "%0", addr, false));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());
        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_EQ(addr.ToString(), link_local);

        // TORv2
        ASSERT_TRUE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsTor());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "6hzph5hv6337r6p2.onion");

        // TORv3
        const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
        ASSERT_TRUE(addr.SetSpecial(torv3_addr));
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsTor());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(!addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), torv3_addr);

        // TORv3, broken, with wrong checksum
        EXPECT_TRUE(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

        // TORv3, broken, with wrong version
        EXPECT_TRUE(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

        // TORv3, malicious (disabled, as we haven't ValidAsCString function and checks yet)

        // EXPECT_TRUE(!addr.SetSpecial(std::string{
        //     "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

        // TOR, bogus length
        EXPECT_TRUE(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

        // TOR, invalid base32
        EXPECT_TRUE(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

        // Internal
        addr.SetInternal("esffpp");
        ASSERT_TRUE(!addr.IsValid()); // "internal" is considered invalid
        ASSERT_TRUE(addr.IsInternal());

        EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_TRUE(addr.IsAddrV1Compatible());
        EXPECT_EQ(addr.ToString(), "esffpvrt3wpeaygy.internal");

        // Totally bogus
        EXPECT_TRUE(!addr.SetSpecial("totally bogus"));
    }

    TEST(TestNetTests, cnetaddr_basic_scoped_link_local) {

        CNetAddr addr;
        std::vector<CNetAddr> vIP;
        // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
        // We support non-negative decimal integers (uint32_t) as zone id indices.
        // Test with a fairly-high value, e.g. 32, to avoid locally reserved ids.
        const std::string link_local{"fe80::1"};
        const std::string scoped_addr{link_local + "%32"};
        ASSERT_TRUE(LookupHost(scoped_addr.c_str(), vIP, false));
        addr = vIP[0];
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());
        //EXPECT_TRUE(!addr.IsBindAny());
        const std::string addr_str{addr.ToString()};
        EXPECT_TRUE(addr_str == scoped_addr || addr_str == "fe80:0:0:0:0:0:0:1");
        // The fallback case "fe80:0:0:0:0:0:0:1" is needed for macOS 10.14/10.15 and (probably) later.
        // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
        const std::string link_local_zone{link_local + "%0"};
        ASSERT_TRUE(LookupHost(link_local_zone.c_str(), vIP, false));
        addr = vIP[0];
        ASSERT_TRUE(addr.IsValid());
        ASSERT_TRUE(addr.IsIPv6());
        //EXPECT_TRUE(!addr.IsBindAny());
        EXPECT_EQ(addr.ToString(), link_local);
    }

    TEST(TestNetTests, cnetaddr_serialize_v1) {
            CNetAddr addr;
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

            s << addr;
            EXPECT_EQ(HexStr(s), "00000000000000000000000000000000");
            s.clear();

            ASSERT_TRUE(LookupHost("1.2.3.4", addr, false));
            s << addr;
            EXPECT_EQ(HexStr(s), "00000000000000000000ffff01020304");
            s.clear();

            ASSERT_TRUE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
            s << addr;
            EXPECT_EQ(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
            s.clear();

            ASSERT_TRUE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
            s << addr;
            EXPECT_EQ(HexStr(s), "fd87d87eeb43f1f2f3f4f5f6f7f8f9fa");
            s.clear();

            ASSERT_TRUE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
            s << addr;
            EXPECT_EQ(HexStr(s), "00000000000000000000000000000000");
            s.clear();

            addr.SetInternal("a");
            s << addr;
            EXPECT_EQ(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
            s.clear();
    }

    TEST(TestNetTests, cnetaddr_serialize_v2) {
        CNetAddr addr;
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        // Add ADDRV2_FORMAT to the version so that the CNetAddr
        // serialize method produces an address in v2 format.
        s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

        s << addr;
        EXPECT_EQ(HexStr(s), "021000000000000000000000000000000000");
        s.clear();

        ASSERT_TRUE(LookupHost("1.2.3.4", addr, false));
        s << addr;
        EXPECT_EQ(HexStr(s), "010401020304");
        s.clear();

        ASSERT_TRUE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
        s << addr;
        EXPECT_EQ(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
        s.clear();

        ASSERT_TRUE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
        s << addr;
        EXPECT_EQ(HexStr(s), "030af1f2f3f4f5f6f7f8f9fa");
        s.clear();

        ASSERT_TRUE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
        s << addr;
        EXPECT_EQ(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
        s.clear();

        ASSERT_TRUE(addr.SetSpecial("deckercu42viy5xss2oxy5rgwong4hxl5rgjethq6xv4y7ko6nc3sdqd.onion"));
        s << addr;
        EXPECT_EQ(HexStr(s), "04201904a24454e6aa8c76f2969d7c7626b39a6e1eebec4c924cf0f5ebcc7d4ef345");
        s.clear();

        ASSERT_TRUE(addr.SetInternal("a"));
        s << addr;
        EXPECT_EQ(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
        s.clear();
    }

    TEST(TestNetTests, cnetaddr_unserialize_v2) {
        CNetAddr addr;
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        // Add ADDRV2_FORMAT to the version so that the CNetAddr
        // unserialize method expects an address in v2 format.
        s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

        // Valid IPv4.
        s << MakeSpan(ParseHex("01"          // network type (IPv4)
                            "04"          // address length
                            "01020304")); // address
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_TRUE(addr.IsIPv4());
        EXPECT_EQ(addr.ToString(), "1.2.3.4");
        ASSERT_TRUE(s.empty());

        // Invalid IPv4, valid length but address itself is shorter.
        s << MakeSpan(ParseHex("01"      // network type (IPv4)
                            "04"      // address length
                            "0102")); // address
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "end of data";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Invalid IPv4, with bogus length.
        s << MakeSpan(ParseHex("01"          // network type (IPv4)
                            "05"          // address length
                            "01020304")); // address
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 IPv4 address with length 5 (should be 4)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Invalid IPv4, with extreme length.
        s << MakeSpan(ParseHex("01"          // network type (IPv4)
                            "fd0102"      // address length (513 as CompactSize)
                            "01020304")); // address
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "Address too long: 513 > 512";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Valid IPv6.
        s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                            "10"                                  // address length
                            "0102030405060708090a0b0c0d0e0f10")); // address
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_TRUE(addr.IsIPv6());
        EXPECT_EQ(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
        ASSERT_TRUE(s.empty());

        // Valid IPv6, contains embedded "internal".
        s << MakeSpan(ParseHex(
            "02"                                  // network type (IPv6)
            "10"                                  // address length
            "fd6b88c08724ca978112ca1bbdcafac2")); // address: 0xfd + sha256("bitcoin")[0:5] +
                                                // sha256(name)[0:10]
        s >> addr;
        EXPECT_TRUE(addr.IsInternal());
        EXPECT_EQ(addr.ToString(), "zklycewkdo64v6wc.internal");
        ASSERT_TRUE(s.empty());

        // Invalid IPv6, with bogus length.
        s << MakeSpan(ParseHex("02"    // network type (IPv6)
                            "04"    // address length
                            "00")); // address
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 IPv6 address with length 4 (should be 16)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Invalid IPv6, contains embedded IPv4.
        s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                            "10"                                  // address length
                            "00000000000000000000ffff01020304")); // address
        s >> addr;
        EXPECT_TRUE(!addr.IsValid());
        ASSERT_TRUE(s.empty());

        // Invalid IPv6, contains embedded TORv2.
        s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                            "10"                                  // address length
                            "fd87d87eeb430102030405060708090a")); // address
        s >> addr;
        EXPECT_TRUE(!addr.IsValid());
        ASSERT_TRUE(s.empty());

        // Valid TORv2.
        s << MakeSpan(ParseHex("03"                      // network type (TORv2)
                            "0a"                      // address length
                            "f1f2f3f4f5f6f7f8f9fa")); // address
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_TRUE(addr.IsTor());
        EXPECT_EQ(addr.ToString(), "6hzph5hv6337r6p2.onion");
        ASSERT_TRUE(s.empty());

        // Invalid TORv2, with bogus length.
        s << MakeSpan(ParseHex("03"    // network type (TORv2)
                            "07"    // address length
                            "00")); // address
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 TORv2 address with length 7 (should be 10)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Valid TORv3.
        s << MakeSpan(ParseHex("04"                               // network type (TORv3)
                            "20"                               // address length
                            "79bcc625184b05194975c28b66b66b04" // address
                            "69f7f6556fb1ac3189a79b40dda32f1f"
                            ));
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_TRUE(addr.IsTor());
        EXPECT_EQ(addr.ToString(),
                        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
        ASSERT_TRUE(s.empty());

        // Invalid TORv3, with bogus length.
        s << MakeSpan(ParseHex("04" // network type (TORv3)
                            "00" // address length
                            "00" // address
                            ));
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 TORv3 address with length 0 (should be 32)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Valid I2P.
        s << MakeSpan(ParseHex("05"                               // network type (I2P)
                            "20"                               // address length
                            "a2894dabaec08c0051a481a6dac88b64" // address
                            "f98232ae42d4b6fd2fa81952dfe36a87"));
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_EQ(addr.ToString(),
                        "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
        ASSERT_TRUE(s.empty());

        // Invalid I2P, with bogus length.
        s << MakeSpan(ParseHex("05" // network type (I2P)
                            "03" // address length
                            "00" // address
                            ));
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 I2P address with length 3 (should be 32)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Valid CJDNS.
        s << MakeSpan(ParseHex("06"                               // network type (CJDNS)
                            "10"                               // address length
                            "fc000001000200030004000500060007" // address
                            ));
        s >> addr;
        EXPECT_TRUE(addr.IsValid());
        EXPECT_EQ(addr.ToString(), "fc00:1:2:3:4:5:6:7");
        ASSERT_TRUE(s.empty());

        // Invalid CJDNS, with bogus length.
        s << MakeSpan(ParseHex("06" // network type (CJDNS)
                            "01" // address length
                            "00" // address
                            ));
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "BIP155 CJDNS address with length 1 (should be 16)";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Unknown, with extreme length.
        s << MakeSpan(ParseHex("aa"             // network type (unknown)
                            "fe00000002"     // address length (CompactSize's MAX_SIZE)
                            "01020304050607" // address
                            ));
        EXPECT_THROW(s >> addr, std::ios_base::failure) << "Address too long: 33554432 > 512";
        ASSERT_TRUE(!s.empty()); // The stream is not consumed on invalid input.
        s.clear();

        // Unknown, with reasonable length.
        s << MakeSpan(ParseHex("aa"       // network type (unknown)
                            "04"       // address length
                            "01020304" // address
                            ));
        s >> addr;
        EXPECT_TRUE(!addr.IsValid());
        ASSERT_TRUE(s.empty());

        // Unknown, with zero length.
        s << MakeSpan(ParseHex("aa" // network type (unknown)
                            "00" // address length
                            ""   // address
                            ));
        s >> addr;
        EXPECT_TRUE(!addr.IsValid());
        ASSERT_TRUE(s.empty());

    }
}
