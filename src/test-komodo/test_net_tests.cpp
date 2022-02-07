#include <gtest/gtest.h>
#include "sync.h"
#include "net.h"

#include <memory>
#include <utility>

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
            uint32_t GetScopeId() { return scopeId; }
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
}