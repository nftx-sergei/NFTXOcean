// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config/bitcoin-config.h"
#endif

#include "netbase.h"

#include "hash.h"
#include "sync.h"
#include "uint256.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "crypto/common.h" // for ReadBE32
#include "crypto/sha3.h"

#ifdef __APPLE__
#ifdef HAVE_GETADDRINFO_A
#undef HAVE_GETADDRINFO_A
#endif
#endif

#ifdef HAVE_GETADDRINFO_A
#include <netdb.h>
#endif

#ifndef _WIN32
#if HAVE_INET_PTON
#include <arpa/inet.h>
#endif
#include <fcntl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/thread.hpp>

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <tuple>

// Settings
static proxyType proxyInfo[NET_MAX];
static proxyType nameProxy;
static CCriticalSection cs_proxyInfos;
int nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
bool fNameLookup = false;

constexpr size_t CNetAddr::V1_SERIALIZATION_SIZE;
constexpr size_t CNetAddr::MAX_ADDRV2_SIZE;

CNetAddr::BIP155Network CNetAddr::GetBIP155Network() const
{
    switch (m_net) {
    case NET_IPV4:
        return BIP155Network::IPV4;
    case NET_IPV6:
        return BIP155Network::IPV6;
    case NET_ONION:
        switch (m_addr.size()) {
        case ADDR_TORV2_SIZE:
            return BIP155Network::TORV2;
        case ADDR_TORV3_SIZE:
            return BIP155Network::TORV3;
        default:
            assert(false);
        }
    case NET_I2P:
        return BIP155Network::I2P;
    case NET_CJDNS:
        return BIP155Network::CJDNS;
    case NET_INTERNAL:   // should have been handled before calling this function
    case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
    case NET_MAX:        // m_net is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

bool CNetAddr::SetNetFromBIP155Network(uint8_t possible_bip155_net, size_t address_size)
{
    switch (possible_bip155_net) {
    case BIP155Network::IPV4:
        if (address_size == ADDR_IPV4_SIZE) {
            m_net = NET_IPV4;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv4 address with length %u (should be %u)", address_size,
                      ADDR_IPV4_SIZE));
    case BIP155Network::IPV6:
        if (address_size == ADDR_IPV6_SIZE) {
            m_net = NET_IPV6;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv6 address with length %u (should be %u)", address_size,
                      ADDR_IPV6_SIZE));
    case BIP155Network::TORV2:
        if (address_size == ADDR_TORV2_SIZE) {
            m_net = NET_ONION;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv2 address with length %u (should be %u)", address_size,
                      ADDR_TORV2_SIZE));
    case BIP155Network::TORV3:
        if (address_size == ADDR_TORV3_SIZE) {
            m_net = NET_ONION;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv3 address with length %u (should be %u)", address_size,
                      ADDR_TORV3_SIZE));
    case BIP155Network::I2P:
        if (address_size == ADDR_I2P_SIZE) {
            m_net = NET_I2P;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 I2P address with length %u (should be %u)", address_size,
                      ADDR_I2P_SIZE));
    case BIP155Network::CJDNS:
        if (address_size == ADDR_CJDNS_SIZE) {
            m_net = NET_CJDNS;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 CJDNS address with length %u (should be %u)", address_size,
                      ADDR_CJDNS_SIZE));
    }

    // Don't throw on addresses with unknown network ids (maybe from the future).
    // Instead silently drop them and have the unserialization code consume
    // subsequent ones which may be known to us.
    return false;
}

// Need ample time for negotiation for very slow proxies such as Tor (milliseconds)
static const int SOCKS5_RECV_TIMEOUT = 20 * 1000;

enum Network ParseNetwork(std::string net) {
    boost::to_lower(net);
    if (net == "ipv4") return NET_IPV4;
    if (net == "ipv6") return NET_IPV6;
    if (net == "tor" || net == "onion")  return NET_ONION;
    return NET_UNROUTABLE;
}

std::string GetNetworkName(enum Network net) {
    switch(net)
    {
    case NET_IPV4: return "ipv4";
    case NET_IPV6: return "ipv6";
    case NET_ONION: return "onion";
    default: return "";
    }
}

void SplitHostPort(std::string in, int &portOut, std::string &hostOut) {
    size_t colon = in.find_last_of(':');
    // if a : is found, and it either follows a [...], or no other : is in the string, treat it as port separator
    bool fHaveColon = colon != in.npos;
    bool fBracketed = fHaveColon && (in[0]=='[' && in[colon-1]==']'); // if there is a colon, and in[0]=='[', colon is not 0, so in[colon-1] is safe
    bool fMultiColon = fHaveColon && (in.find_last_of(':',colon-1) != in.npos);
    if (fHaveColon && (colon==0 || fBracketed || !fMultiColon)) {
        int32_t n;
        if (ParseInt32(in.substr(colon + 1), &n) && n > 0 && n < 0x10000) {
            in = in.substr(0, colon);
            portOut = n;
        }
    }
    if (in.size()>0 && in[0] == '[' && in[in.size()-1] == ']')
        hostOut = in.substr(1, in.size()-2);
    else
        hostOut = in;
}

bool static LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

#ifdef HAVE_GETADDRINFO_A
    struct in_addr ipv4_addr;
#ifdef HAVE_INET_PTON
    if (inet_pton(AF_INET, pszName, &ipv4_addr) > 0) {
        vIP.push_back(CNetAddr(ipv4_addr));
        return true;
    }

    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, pszName, &ipv6_addr) > 0) {
        vIP.push_back(CNetAddr(ipv6_addr));
        return true;
    }
#else
    ipv4_addr.s_addr = inet_addr(pszName);
    if (ipv4_addr.s_addr != INADDR_NONE) {
        vIP.push_back(CNetAddr(ipv4_addr));
        return true;
    }
#endif
#endif

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));
    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
    aiHint.ai_family = AF_UNSPEC;
#ifdef _WIN32
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif

    struct addrinfo *aiRes = NULL;
#ifdef HAVE_GETADDRINFO_A
    struct gaicb gcb, *query = &gcb;
    memset(query, 0, sizeof(struct gaicb));
    gcb.ar_name = pszName;
    gcb.ar_request = &aiHint;
    int nErr = getaddrinfo_a(GAI_NOWAIT, &query, 1, NULL);
    if (nErr)
        return false;

    do {
        // Should set the timeout limit to a reasonable value to avoid
        // generating unnecessary checking call during the polling loop,
        // while it can still response to stop request quick enough.
        // 2 seconds looks fine in our situation.
        struct timespec ts = { 2, 0 };
        gai_suspend(&query, 1, &ts);
        boost::this_thread::interruption_point();

        nErr = gai_error(query);
        if (0 == nErr)
            aiRes = query->ar_result;
    } while (nErr == EAI_INPROGRESS);
#else
    int nErr = getaddrinfo(pszName, NULL, &aiHint, &aiRes);
#endif
    if (nErr)
        return false;

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != NULL && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        boost::this_thread::interruption_point();

        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            vIP.push_back(CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr));
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            struct sockaddr_in6* s6 = (struct sockaddr_in6*) aiTrav->ai_addr;
            vIP.push_back(CNetAddr(s6->sin6_addr, s6->sin6_scope_id));
        }

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return (vIP.size() > 0);
}

bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    std::string strHost(pszName);
    if (strHost.empty())
        return false;
    if (boost::algorithm::starts_with(strHost, "[") && boost::algorithm::ends_with(strHost, "]"))
    {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
}

/**
 * Resolve a host string to its corresponding network addresses.
 *
 * @param name    The string representing a host. Could be a name or a numerical
 *                IP address (IPv6 addresses in their bracketed form are
 *                allowed).
 * @param[out] vIP The resulting network addresses to which the specified host
 *                 string resolved.
 *
 * @returns Whether or not the specified host string successfully resolved to
 *          any resulting network addresses.
 *
 * @see Lookup(const char *, std::vector<CService>&, int, bool, unsigned int)
 *      for additional parameter descriptions.
 */
bool LookupHost(const std::string& name, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    std::string strHost = name;
    if (strHost.empty())
        return false;
    if (strHost.front() == '[' && strHost.back() == ']') {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
}

 /**
 * Resolve a host string to its first corresponding network address.
 *
 * @see LookupHost(const std::string&, std::vector<CNetAddr>&, unsigned int, bool) for
 *      additional parameter descriptions.
 */
bool LookupHost(const std::string& name, CNetAddr& addr, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    LookupHost(name, vIP, 1, fAllowLookup);
    if(vIP.empty())
        return false;
    addr = vIP.front();
    return true;
}

bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions)
{
    if (pszName[0] == 0)
        return false;
    int port = portDefault;
    std::string hostname = "";
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (!fRet)
        return false;
    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); i++)
        vAddr[i] = CService(vIP[i], port);
    return true;
}

bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup)
{
    std::vector<CService> vService;
    bool fRet = Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (!fRet)
        return false;
    addr = vService[0];
    return true;
}

bool LookupNumeric(const char *pszName, CService& addr, int portDefault)
{
    return Lookup(pszName, addr, portDefault, false);
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

/**
 * Read bytes from socket. This will either read the full number of bytes requested
 * or return False on error or timeout.
 * This function can be interrupted by boost thread interrupt.
 *
 * @param data Buffer to receive into
 * @param len  Length of data to receive
 * @param timeout  Timeout in milliseconds for receive operation
 *
 * @note This function requires that hSocket is in non-blocking mode.
 */
bool static InterruptibleRecv(uint8_t* data, size_t len, int timeout, SOCKET& hSocket)
{
    int64_t curTime = GetTimeMillis();
    int64_t endTime = curTime + timeout;
    // Maximum time to wait in one select call. It will take up until this time (in millis)
    // to break off in case of an interruption.
    const int64_t maxWait = 1000;
    while (len > 0 && curTime < endTime) {
#ifdef WIN32
        ssize_t ret = recv(hSocket, (char*)data, len, 0); // Optimistically try the recv first
#else
        ssize_t ret = recv(hSocket, data, len, 0); // Optimistically try the recv first
#endif
        if (ret > 0) {
            len -= ret;
            data += ret;
        } else if (ret == 0) { // Unexpected disconnection
            return false;
        } else { // Other error or blocking
            int nErr = WSAGetLastError();
            if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL) {
                if (!IsSelectableSocket(hSocket)) {
                    return false;
                }
                struct timeval tval = MillisToTimeval(std::min(endTime - curTime, maxWait));
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(hSocket, &fdset);
                int nRet = select(hSocket + 1, &fdset, NULL, NULL, &tval);
                if (nRet == SOCKET_ERROR) {
                    return false;
                }
            } else {
                return false;
            }
        }
        boost::this_thread::interruption_point();
        curTime = GetTimeMillis();
    }
    return len == 0;
}

struct ProxyCredentials
{
    std::string username;
    std::string password;
};

/** Connect using SOCKS5 (as described in RFC1928) */
static bool Socks5(const std::string& strDest, int port, const ProxyCredentials *auth, SOCKET& hSocket)
{
    LogPrintf("SOCKS5 connecting %s\n", strDest);
    if (strDest.size() > 255) {
        CloseSocket(hSocket);
        return error("Hostname too long");
    }
    // Accepted authentication methods
    std::vector<uint8_t> vSocks5Init;
    vSocks5Init.push_back(0x05);
    if (auth) {
        vSocks5Init.push_back(0x02); // # METHODS
        vSocks5Init.push_back(0x00); // X'00' NO AUTHENTICATION REQUIRED
        vSocks5Init.push_back(0x02); // X'02' USERNAME/PASSWORD (RFC1929)
    } else {
        vSocks5Init.push_back(0x01); // # METHODS
        vSocks5Init.push_back(0x00); // X'00' NO AUTHENTICATION REQUIRED
    }
    ssize_t ret = send(hSocket, (const char*)begin_ptr(vSocks5Init), vSocks5Init.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5Init.size()) {
        CloseSocket(hSocket);
        return error("Error sending to proxy");
    }
    uint8_t pchRet1[2];
    if (!InterruptibleRecv(pchRet1, 2, SOCKS5_RECV_TIMEOUT, hSocket)) {
        CloseSocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet1[0] != 0x05) {
        CloseSocket(hSocket);
        return error("Proxy failed to initialize");
    }
    if (pchRet1[1] == 0x02 && auth) {
        // Perform username/password authentication (as described in RFC1929)
        std::vector<uint8_t> vAuth;
        vAuth.push_back(0x01);
        if (auth->username.size() > 255 || auth->password.size() > 255)
            return error("Proxy username or password too long");
        vAuth.push_back(auth->username.size());
        vAuth.insert(vAuth.end(), auth->username.begin(), auth->username.end());
        vAuth.push_back(auth->password.size());
        vAuth.insert(vAuth.end(), auth->password.begin(), auth->password.end());
        ret = send(hSocket, (const char*)begin_ptr(vAuth), vAuth.size(), MSG_NOSIGNAL);
        if (ret != (ssize_t)vAuth.size()) {
            CloseSocket(hSocket);
            return error("Error sending authentication to proxy");
        }
        LogPrint("proxy", "SOCKS5 sending proxy authentication %s:%s\n", auth->username, auth->password);
        uint8_t pchRetA[2];
        if (!InterruptibleRecv(pchRetA, 2, SOCKS5_RECV_TIMEOUT, hSocket)) {
            CloseSocket(hSocket);
            return error("Error reading proxy authentication response");
        }
        if (pchRetA[0] != 0x01 || pchRetA[1] != 0x00) {
            CloseSocket(hSocket);
            return error("Proxy authentication unsuccessful");
        }
    } else if (pchRet1[1] == 0x00) {
        // Perform no authentication
    } else {
        CloseSocket(hSocket);
        return error("Proxy requested wrong authentication method %02x", pchRet1[1]);
    }
    std::vector<uint8_t> vSocks5;
    vSocks5.push_back(0x05); // VER protocol version
    vSocks5.push_back(0x01); // CMD CONNECT
    vSocks5.push_back(0x00); // RSV Reserved
    vSocks5.push_back(0x03); // ATYP DOMAINNAME
    vSocks5.push_back(strDest.size()); // Length<=255 is checked at beginning of function
    vSocks5.insert(vSocks5.end(), strDest.begin(), strDest.end());
    vSocks5.push_back((port >> 8) & 0xFF);
    vSocks5.push_back((port >> 0) & 0xFF);
    ret = send(hSocket, (const char*)begin_ptr(vSocks5), vSocks5.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5.size()) {
        CloseSocket(hSocket);
        return error("Error sending to proxy");
    }
    uint8_t pchRet2[4];
    if (!InterruptibleRecv(pchRet2, 4, SOCKS5_RECV_TIMEOUT, hSocket)) {
        CloseSocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet2[0] != 0x05) {
        CloseSocket(hSocket);
        return error("Proxy failed to accept request");
    }
    if (pchRet2[1] != 0x00) {
        CloseSocket(hSocket);
        switch (pchRet2[1])
        {
            case 0x01: return error("Proxy error: general failure");
            case 0x02: return error("Proxy error: connection not allowed");
            case 0x03: return error("Proxy error: network unreachable");
            case 0x04: return error("Proxy error: host unreachable");
            case 0x05: return error("Proxy error: connection refused");
            case 0x06: return error("Proxy error: TTL expired");
            case 0x07: return error("Proxy error: protocol error");
            case 0x08: return error("Proxy error: address type not supported");
            default:   return error("Proxy error: unknown");
        }
    }
    if (pchRet2[2] != 0x00) {
        CloseSocket(hSocket);
        return error("Error: malformed proxy response");
    }
    uint8_t pchRet3[256];
    switch (pchRet2[3])
    {
        case 0x01: ret = InterruptibleRecv(pchRet3, 4, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case 0x04: ret = InterruptibleRecv(pchRet3, 16, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case 0x03:
        {
            ret = InterruptibleRecv(pchRet3, 1, SOCKS5_RECV_TIMEOUT, hSocket);
            if (!ret) {
                CloseSocket(hSocket);
                return error("Error reading from proxy");
            }
            size_t nRecv = pchRet3[0];
            ret = InterruptibleRecv(pchRet3, nRecv, SOCKS5_RECV_TIMEOUT, hSocket);
            break;
        }
        default: CloseSocket(hSocket); return error("Error: malformed proxy response");
    }
    if (!ret) {
        CloseSocket(hSocket);
        return error("Error reading from proxy");
    }
    if (!InterruptibleRecv(pchRet3, 2, SOCKS5_RECV_TIMEOUT, hSocket)) {
        CloseSocket(hSocket);
        return error("Error reading from proxy");
    }
    LogPrintf("SOCKS5 connected %s\n", strDest);
    return true;
}

bool static ConnectSocketDirectly(const CService &addrConnect, SOCKET& hSocketRet, int nTimeout)
{
    hSocketRet = INVALID_SOCKET;

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot connect to %s: unsupported network\n", addrConnect.ToString());
        return false;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return false;

    int set = 1;
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    //Disable Nagle's algorithm
#ifdef _WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true))
        return error("ConnectSocketDirectly: Setting socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));

    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL)
        {
            struct timeval timeout = MillisToTimeval(nTimeout);
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, NULL, &fdset, NULL, &timeout);
            if (nRet == 0)
            {
                LogPrint("net", "connection to %s timeout\n", addrConnect.ToString());
                CloseSocket(hSocket);
                return false;
            }
            if (nRet == SOCKET_ERROR)
            {
                LogPrintf("select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }
            socklen_t nRetSize = sizeof(nRet);
#ifdef _WIN32
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                LogPrintf("getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }
            if (nRet != 0)
            {
                LogPrintf("connect() to %s failed after select(): %s\n", addrConnect.ToString(), NetworkErrorString(nRet));
                CloseSocket(hSocket);
                return false;
            }
        }
#ifdef _WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            if ( NetworkErrorString(WSAGetLastError()) != "Network is unreachable (101)")
                LogPrintf("connect() to %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            CloseSocket(hSocket);
            return false;
        }
    }

    hSocketRet = hSocket;
    return true;
}

bool SetProxy(enum Network net, const proxyType &addrProxy) {
    assert(net >= 0 && net < NET_MAX);
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    proxyInfo[net] = addrProxy;
    return true;
}

bool GetProxy(enum Network net, proxyType &proxyInfoOut) {
    assert(net >= 0 && net < NET_MAX);
    LOCK(cs_proxyInfos);
    if (!proxyInfo[net].IsValid())
        return false;
    proxyInfoOut = proxyInfo[net];
    return true;
}

bool SetNameProxy(const proxyType &addrProxy) {
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    nameProxy = addrProxy;
    return true;
}

bool GetNameProxy(proxyType &nameProxyOut) {
    LOCK(cs_proxyInfos);
    if(!nameProxy.IsValid())
        return false;
    nameProxyOut = nameProxy;
    return true;
}

bool HaveNameProxy() {
    LOCK(cs_proxyInfos);
    return nameProxy.IsValid();
}

bool IsProxy(const CNetAddr &addr) {
    LOCK(cs_proxyInfos);
    for (int i = 0; i < NET_MAX; i++) {
        if (addr == (CNetAddr)proxyInfo[i].proxy)
            return true;
    }
    return false;
}

static bool ConnectThroughProxy(const proxyType &proxy, const std::string& strDest, int port, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed)
{
    SOCKET hSocket = INVALID_SOCKET;
    // first connect to proxy server
    if (!ConnectSocketDirectly(proxy.proxy, hSocket, nTimeout)) {
        if (outProxyConnectionFailed)
            *outProxyConnectionFailed = true;
        return false;
    }
    // do socks negotiation
    if (proxy.randomize_credentials) {
        ProxyCredentials random_auth;
        random_auth.username = strprintf("%i", insecure_rand());
        random_auth.password = strprintf("%i", insecure_rand());
        if (!Socks5(strDest, (unsigned short)port, &random_auth, hSocket))
            return false;
    } else {
        if (!Socks5(strDest, (unsigned short)port, 0, hSocket))
            return false;
    }

    hSocketRet = hSocket;
    return true;
}

bool ConnectSocket(const CService &addrDest, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed)
{
    proxyType proxy;
    if (outProxyConnectionFailed)
        *outProxyConnectionFailed = false;

    if (GetProxy(addrDest.GetNetwork(), proxy))
        return ConnectThroughProxy(proxy, addrDest.ToStringIP(), addrDest.GetPort(), hSocketRet, nTimeout, outProxyConnectionFailed);
    else // no proxy needed (none set for target network)
        return ConnectSocketDirectly(addrDest, hSocketRet, nTimeout);
}

bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault, int nTimeout, bool *outProxyConnectionFailed)
{
    std::string strDest;
    int port = portDefault;

    if (outProxyConnectionFailed)
        *outProxyConnectionFailed = false;

    SplitHostPort(std::string(pszDest), port, strDest);

    proxyType nameProxy;
    GetNameProxy(nameProxy);

    CService addrResolved(CNetAddr(strDest, fNameLookup && !HaveNameProxy()), port);
    if (addrResolved.IsValid()) {
        addr = addrResolved;
        return ConnectSocket(addr, hSocketRet, nTimeout);
    }

    addr = CService("0.0.0.0:0");

    if (!HaveNameProxy())
        return false;
    return ConnectThroughProxy(nameProxy, strDest, port, hSocketRet, nTimeout, outProxyConnectionFailed);
}

/**
 * Create an "internal" address that represents a name or FQDN. CAddrMan uses
 * these fake addresses to keep track of which DNS seeds were used.
 * @returns Whether or not the operation was successful.
 * @see NET_INTERNAL, INTERNAL_IN_IPV6_PREFIX, CNetAddr::IsInternal(), CNetAddr::IsRFC4193()
 */
bool CNetAddr::SetInternal(const std::string &name)
{
    if (name.empty()) {
        return false;
    }
    m_net = NET_INTERNAL;
    unsigned char hash[32] = {};
    CSHA256().Write((const unsigned char*)name.data(), name.size()).Finalize(hash);
    m_addr.assign(hash, hash + ADDR_INTERNAL_SIZE);
    return true;
}

namespace torv3 {
// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
static constexpr size_t CHECKSUM_LEN = 2;
static const unsigned char VERSION[] = {3};
static constexpr size_t TOTAL_LEN = ADDR_TORV3_SIZE + CHECKSUM_LEN + sizeof(VERSION);

static void Checksum(Span<const uint8_t> addr_pubkey, uint8_t (&checksum)[CHECKSUM_LEN])
{
    // TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    static const unsigned char prefix[] = ".onion checksum";
    static constexpr size_t prefix_len = 15;

    SHA3_256 hasher;

    hasher.Write(MakeSpan(prefix).first(prefix_len));
    hasher.Write(addr_pubkey);
    hasher.Write(VERSION);

    uint8_t checksum_full[SHA3_256::OUTPUT_SIZE];

    hasher.Finalize(checksum_full);

    memcpy(checksum, checksum_full, sizeof(checksum));
}

}; // namespace torv3

/**
 * Parse a TOR address and set this object to it.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsTor()
 */
bool CNetAddr::SetSpecial(const std::string& str)
{
    static const char* suffix{".onion"};
    static constexpr size_t suffix_len{6};

    if (str.size() <= suffix_len ||
        str.substr(str.size() - suffix_len) != suffix) {
        return false;
    }

    bool invalid;
    const auto& input = DecodeBase32(str.substr(0, str.size() - suffix_len).c_str(), &invalid);

    if (invalid) {
        return false;
    }

    switch (input.size()) {
    case ADDR_TORV2_SIZE:
        m_net = NET_ONION;
        m_addr.assign(input.begin(), input.end());
        return true;
    case torv3::TOTAL_LEN: {
        Span<const uint8_t> input_pubkey{input.data(), ADDR_TORV3_SIZE};
        Span<const uint8_t> input_checksum{input.data() + ADDR_TORV3_SIZE, torv3::CHECKSUM_LEN};
        Span<const uint8_t> input_version{input.data() + ADDR_TORV3_SIZE + torv3::CHECKSUM_LEN, sizeof(torv3::VERSION)};

        uint8_t calculated_checksum[torv3::CHECKSUM_LEN];
        torv3::Checksum(input_pubkey, calculated_checksum);

        if (input_checksum != calculated_checksum || input_version != torv3::VERSION) {
            return false;
        }

        m_net = NET_ONION;
        m_addr.assign(input_pubkey.begin(), input_pubkey.end());
        return true;
    }
    }

    return false;
}

void CNetAddr::SetIP(const CNetAddr& ipIn)
{
    // Size check.
    switch (ipIn.m_net) {
    case NET_IPV4:
        assert(ipIn.m_addr.size() == ADDR_IPV4_SIZE);
        break;
    case NET_IPV6:
        assert(ipIn.m_addr.size() == ADDR_IPV6_SIZE);
        break;
    case NET_ONION:
        assert(ipIn.m_addr.size() == ADDR_TORV2_SIZE || ipIn.m_addr.size() == ADDR_TORV3_SIZE);
        break;
    case NET_I2P:
        assert(ipIn.m_addr.size() == ADDR_I2P_SIZE);
        break;
    case NET_CJDNS:
        assert(ipIn.m_addr.size() == ADDR_CJDNS_SIZE);
        break;
    case NET_INTERNAL:
        assert(ipIn.m_addr.size() == ADDR_INTERNAL_SIZE);
        break;
    case NET_UNROUTABLE:
    case NET_MAX:
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    m_net = ipIn.m_net;
    m_addr = ipIn.m_addr;
}

void CNetAddr::SetLegacyIPv6(Span<const uint8_t> ipv6)
{
    assert(ipv6.size() == ADDR_IPV6_SIZE);

    size_t skip{0};

    if (HasPrefix(ipv6, IPV4_IN_IPV6_PREFIX)) {
        // IPv4-in-IPv6
        m_net = NET_IPV4;
        skip = sizeof(IPV4_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6, TORV2_IN_IPV6_PREFIX)) {
        // TORv2-in-IPv6
        m_net = NET_ONION;
        skip = sizeof(TORV2_IN_IPV6_PREFIX);
    } else if (HasPrefix(ipv6, INTERNAL_IN_IPV6_PREFIX)) {
        // Internal-in-IPv6
        m_net = NET_INTERNAL;
        skip = sizeof(INTERNAL_IN_IPV6_PREFIX);
    } else {
        // IPv6
        m_net = NET_IPV6;
    }

    m_addr.assign(ipv6.begin() + skip, ipv6.end());
}

CNetAddr::CNetAddr() {}

CNetAddr::CNetAddr(const struct in_addr& ipv4Addr)
{
    m_net = NET_IPV4;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&ipv4Addr);
    m_addr.assign(ptr, ptr + ADDR_IPV4_SIZE);
}

CNetAddr::CNetAddr(const struct in6_addr& ipv6Addr, const uint32_t scope)
{
    SetLegacyIPv6(Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&ipv6Addr), sizeof(ipv6Addr)));
    m_scope_id = scope;
}

CNetAddr::CNetAddr(const char *pszIp, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    if (LookupHost(pszIp, vIP, 1, fAllowLookup))
        *this = vIP[0];
}

CNetAddr::CNetAddr(const std::string &strIp, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    if (LookupHost(strIp.c_str(), vIP, 1, fAllowLookup))
        *this = vIP[0];
}

bool CNetAddr::IsBindAny() const
{
    if (!IsIPv4() && !IsIPv6()) {
        return false;
    }
    return std::all_of(m_addr.begin(), m_addr.end(), [](uint8_t b) { return b == 0; });
}

bool CNetAddr::IsIPv4() const { return m_net == NET_IPV4; }

bool CNetAddr::IsIPv6() const { return m_net == NET_IPV6; }

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() && (
        m_addr[0] == 10 ||
        (m_addr[0] == 192 && m_addr[1] == 168) ||
        (m_addr[0] == 172 && m_addr[1] >= 16 && m_addr[1] <= 31));
}

bool CNetAddr::IsRFC2544() const
{
    return IsIPv4() && m_addr[0] == 198 && (m_addr[1] == 18 || m_addr[1] == 19);
}

bool CNetAddr::IsRFC3927() const
{
    return IsIPv4() && HasPrefix(m_addr, std::array<uint8_t, 2>{169, 254});
}

bool CNetAddr::IsRFC6598() const
{
    return IsIPv4() && m_addr[0] == 100 && m_addr[1] >= 64 && m_addr[1] <= 127;
}

bool CNetAddr::IsRFC5737() const
{
    return IsIPv4() && (HasPrefix(m_addr, std::array<uint8_t, 3>{192, 0, 2}) ||
                        HasPrefix(m_addr, std::array<uint8_t, 3>{198, 51, 100}) ||
                        HasPrefix(m_addr, std::array<uint8_t, 3>{203, 0, 113}));
}

bool CNetAddr::IsRFC3849() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{0x20, 0x01, 0x0D, 0xB8});
}

bool CNetAddr::IsRFC3964() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 2>{0x20, 0x02});
}

bool CNetAddr::IsRFC6052() const
{
    return IsIPv6() &&
           HasPrefix(m_addr, std::array<uint8_t, 12>{0x00, 0x64, 0xFF, 0x9B, 0x00, 0x00,
                                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
}

bool CNetAddr::IsRFC4380() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{0x20, 0x01, 0x00, 0x00});
}

bool CNetAddr::IsRFC4862() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 8>{0xFE, 0x80, 0x00, 0x00,
                                                                0x00, 0x00, 0x00, 0x00});
}

bool CNetAddr::IsRFC4193() const
{
    return IsIPv6() && (m_addr[0] & 0xFE) == 0xFC;
}

bool CNetAddr::IsRFC6145() const
{
    return IsIPv6() &&
           HasPrefix(m_addr, std::array<uint8_t, 12>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                     0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00});
}

bool CNetAddr::IsRFC4843() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 3>{0x20, 0x01, 0x00}) &&
           (m_addr[3] & 0xF0) == 0x10;
}

bool CNetAddr::IsRFC7343() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 3>{0x20, 0x01, 0x00}) &&
           (m_addr[3] & 0xF0) == 0x20;
}

bool CNetAddr::IsHeNet() const
{
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{0x20, 0x01, 0x04, 0x70});
}

/**
 * Check whether this object represents a TOR address.
 * @see CNetAddr::SetSpecial(const std::string &)
 */
bool CNetAddr::IsTor() const { return m_net == NET_ONION; }

/**
 * Check whether this object represents an I2P address.
 */
bool CNetAddr::IsI2P() const { return m_net == NET_I2P; }

/**
 * Check whether this object represents a CJDNS address.
 */
bool CNetAddr::IsCJDNS() const { return m_net == NET_CJDNS; }

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback (127.0.0.0/8 or 0.0.0.0/8)
    if (IsIPv4() && (m_addr[0] == 127 || m_addr[0] == 0)) {
       return true;
    }

   // IPv6 loopback (::1/128)
   static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (IsIPv6() && memcmp(m_addr.data(), pchLocal, sizeof(pchLocal)) == 0) {
       return true;
    }

   return false;
}

/**
 * @returns Whether or not this network address is a valid address that @a could
 *          be used to refer to an actual host.
 *
 * @note A valid address may or may not be publicly routable on the global
 *       internet. As in, the set of valid addresses is a superset of the set of
 *       publicly routable addresses.
 *
 * @see CNetAddr::IsRoutable()
 */
bool CNetAddr::IsValid() const
{
    // unspecified IPv6 address (::/128)
    unsigned char ipNone6[16] = {};
    if (IsIPv6() && memcmp(m_addr.data(), ipNone6, sizeof(ipNone6)) == 0) {
        return false;
    }

    // documentation IPv6 address
    if (IsRFC3849())
        return false;

    if (IsInternal())
        return false;

    if (IsIPv4()) {
        const uint32_t addr = ReadBE32(m_addr.data());
        if (addr == INADDR_ANY || addr == INADDR_NONE) {
            return false;
        }
    }

    return true;
}

/**
 * @returns Whether or not this network address is publicly routable on the
 *          global internet.
 *
 * @note A routable address is always valid. As in, the set of routable addresses
 *       is a subset of the set of valid addresses.
 *
 * @see CNetAddr::IsValid()
 */
bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsTor()) || IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());
}

/**
 * @returns Whether or not this is a dummy address that represents a name.
 *
 * @see CNetAddr::SetInternal(const std::string &)
 */
bool CNetAddr::IsInternal() const
{
    return m_net == NET_INTERNAL;
}

enum Network CNetAddr::GetNetwork() const
{
    if (IsInternal())
        return NET_INTERNAL;

    if (!IsRoutable())
        return NET_UNROUTABLE;

    return m_net;
}

static std::string IPv6ToString(Span<const uint8_t> a)
{
    assert(a.size() == ADDR_IPV6_SIZE);
    // clang-format off
    return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                     ReadBE16(&a[0]),
                     ReadBE16(&a[2]),
                     ReadBE16(&a[4]),
                     ReadBE16(&a[6]),
                     ReadBE16(&a[8]),
                     ReadBE16(&a[10]),
                     ReadBE16(&a[12]),
                     ReadBE16(&a[14]));
    // clang-format on
}

std::string CNetAddr::ToStringIP() const
{
    switch (m_net) {
    case NET_IPV4:
    case NET_IPV6: {
        CService serv(*this, 0);
        struct sockaddr_storage sockaddr;
        socklen_t socklen = sizeof(sockaddr);
        if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
            char name[1025] = "";
            if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name,
                             sizeof(name), nullptr, 0, NI_NUMERICHOST))
                return std::string(name);
        }
        if (m_net == NET_IPV4) {
            return strprintf("%u.%u.%u.%u", m_addr[0], m_addr[1], m_addr[2], m_addr[3]);
        }
        return IPv6ToString(m_addr);
    }
    case NET_ONION:
        switch (m_addr.size()) {
        case ADDR_TORV2_SIZE:
            return EncodeBase32(m_addr) + ".onion";
        case ADDR_TORV3_SIZE: {

            uint8_t checksum[torv3::CHECKSUM_LEN];
            torv3::Checksum(m_addr, checksum);

            // TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
            prevector<torv3::TOTAL_LEN, uint8_t> address{m_addr.begin(), m_addr.end()};
            address.insert(address.end(), checksum, checksum + torv3::CHECKSUM_LEN);
            address.insert(address.end(), torv3::VERSION, torv3::VERSION + sizeof(torv3::VERSION));

            return EncodeBase32(address) + ".onion";
        }
        default:
            assert(false);
        }
    case NET_I2P:
        return EncodeBase32(m_addr, false /* don't pad with = */) + ".b32.i2p";
    case NET_CJDNS:
        return IPv6ToString(m_addr);
    case NET_INTERNAL:
        return EncodeBase32(m_addr) + ".internal";
    case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
    case NET_MAX:        // m_net is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return a.m_net == b.m_net && a.m_addr == b.m_addr;
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    return std::tie(a.m_net, a.m_addr) < std::tie(b.m_net, b.m_addr);
}

/**
 * Try to get our IPv4 address.
 *
 * @param[out] pipv4Addr The in_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv4 address.
 *
 * @see CNetAddr::IsIPv4()
 */
bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
{
    if (!IsIPv4())
        return false;
    assert(sizeof(*pipv4Addr) == m_addr.size());
    memcpy(pipv4Addr, m_addr.data(), m_addr.size());
    return true;
}

/**
 * Try to get our IPv6 address.
 *
 * @param[out] pipv6Addr The in6_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv6 address.
 *
 * @see CNetAddr::IsIPv6()
 */
bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
{
    if (!IsIPv6()) {
        return false;
    }
    assert(sizeof(*pipv6Addr) == m_addr.size());
    memcpy(pipv6Addr, m_addr.data(), m_addr.size());
    return true;
}

bool CNetAddr::HasLinkedIPv4() const
{
    return IsRoutable() && (IsIPv4() || IsRFC6145() || IsRFC6052() || IsRFC3964() || IsRFC4380());
}

uint32_t CNetAddr::GetLinkedIPv4() const
{
    if (IsIPv4()) {
        return ReadBE32(m_addr.data());
    } else if (IsRFC6052() || IsRFC6145()) {
        // mapped IPv4, SIIT translated IPv4: the IPv4 address is the last 4 bytes of the address
        return ReadBE32(MakeSpan(m_addr).last(ADDR_IPV4_SIZE).data());
    } else if (IsRFC3964()) {
        // 6to4 tunneled IPv4: the IPv4 address is in bytes 2-6
        return ReadBE32(MakeSpan(m_addr).subspan(2, ADDR_IPV4_SIZE).data());
    } else if (IsRFC4380()) {
        // Teredo tunneled IPv4: the IPv4 address is in the last 4 bytes of the address, but bitflipped
        return ~ReadBE32(MakeSpan(m_addr).last(ADDR_IPV4_SIZE).data());
    }
    assert(false);
}

uint32_t CNetAddr::GetNetClass() const
{
    // Make sure that if we return NET_IPV6, then IsIPv6() is true. The callers expect that.

    // Check for "internal" first because such addresses are also !IsRoutable()
    // and we don't want to return NET_UNROUTABLE in that case.
    if (IsInternal()) {
        return NET_INTERNAL;
    }
    if (!IsRoutable()) {
        return NET_UNROUTABLE;
    }
    if (HasLinkedIPv4()) {
        return NET_IPV4;
    }
    return m_net;
}

uint32_t CNetAddr::GetMappedAS(const std::vector<bool> &asmap) const {
    uint32_t net_class = GetNetClass();
    if (asmap.size() == 0 || (net_class != NET_IPV4 && net_class != NET_IPV6)) {
        return 0; // Indicates not found, safe because AS0 is reserved per RFC7607.
    }
    std::vector<bool> ip_bits(128);
    if (HasLinkedIPv4()) {
        // For lookup, treat as if it was just an IPv4 address (IPV4_IN_IPV6_PREFIX + IPv4 bits)
        for (int8_t byte_i = 0; byte_i < 12; ++byte_i) {
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (IPV4_IN_IPV6_PREFIX[byte_i] >> (7 - bit_i)) & 1;
            }
        }
        uint32_t ipv4 = GetLinkedIPv4();
        for (int i = 0; i < 32; ++i) {
            ip_bits[96 + i] = (ipv4 >> (31 - i)) & 1;
        }
    } else {
        // Use all 128 bits of the IPv6 address otherwise
        assert(IsIPv6());
        for (int8_t byte_i = 0; byte_i < 16; ++byte_i) {
            uint8_t cur_byte = m_addr[byte_i];
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (cur_byte >> (7 - bit_i)) & 1;
            }
        }
    }
    uint32_t mapped_as = Interpret(asmap, ip_bits);
    return mapped_as;
}

/**
 * Get the canonical identifier of our network group
 *
 * The groups are assigned in a way where it should be costly for an attacker to
 * obtain addresses with many different group identifiers, even if it is cheap
 * to obtain addresses with the same identifier.
 *
 * @note No two connections will be attempted to addresses with the same network
 *       group.
 */
std::vector<unsigned char> CNetAddr::GetGroup(const std::vector<bool> &asmap) const
{
    std::vector<unsigned char> vchRet;
    uint32_t net_class = GetNetClass();
    // If non-empty asmap is supplied and the address is IPv4/IPv6,
    // return ASN to be used for bucketing.
    uint32_t asn = GetMappedAS(asmap);
    if (asn != 0) { // Either asmap was empty, or address has non-asmappable net class (e.g. TOR).
        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN should be in the same bucket
        for (int i = 0; i < 4; i++) {
            vchRet.push_back((asn >> (8 * i)) & 0xFF);
        }
        return vchRet;
    }

    vchRet.push_back(net_class);
    int nBits{0};

    if (IsLocal()) {
        // all local addresses belong to the same group
    } else if (IsInternal()) {
        // all internal-usage addresses get their own group
        nBits = ADDR_INTERNAL_SIZE * 8;
    } else if (!IsRoutable()) {
        // all other unroutable addresses belong to the same group
    } else if (HasLinkedIPv4()) {
        // IPv4 addresses (and mapped IPv4 addresses) use /16 groups
        uint32_t ipv4 = GetLinkedIPv4();
        vchRet.push_back((ipv4 >> 24) & 0xFF);
        vchRet.push_back((ipv4 >> 16) & 0xFF);
        return vchRet;
    } else if (IsTor() || IsI2P() || IsCJDNS()) {
        nBits = 4;
    } else if (IsHeNet()) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    // Push our address onto vchRet.
    const size_t num_bytes = nBits / 8;
    vchRet.insert(vchRet.end(), m_addr.begin(), m_addr.begin() + num_bytes);
    nBits %= 8;
    // ...for the last byte, push nBits and for the rest of the byte push 1's
    if (nBits > 0) {
        assert(num_bytes < m_addr.size());
        vchRet.push_back(m_addr[num_bytes] | ((1 << (8 - nBits)) - 1));
    }

    return vchRet;
}

std::vector<unsigned char> CNetAddr::GetAddrBytes() const
{
    uint8_t serialized[V1_SERIALIZATION_SIZE];
    SerializeV1Array(serialized);
    return {std::begin(serialized), std::end(serialized)};
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(m_addr.begin(), m_addr.end());
    uint64_t nRet;
    memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == nullptr)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable() || IsInternal())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch(theirNet) {
    case NET_IPV4:
        switch(ourNet) {
        default:       return REACH_DEFAULT;
        case NET_IPV4: return REACH_IPV4;
        }
    case NET_IPV6:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_TEREDO: return REACH_TEREDO;
        case NET_IPV4:   return REACH_IPV4;
        case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_ONION:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_ONION:    return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case NET_UNROUTABLE:
    default:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        case NET_ONION:     return REACH_PRIVATE; // either from Tor, or don't care about our address
        }
    }
}

void CService::Init()
{
    port = 0;
}

CService::CService()
{
    Init();
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

CService::CService(const struct in_addr& ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn)
{
}

CService::CService(const struct in6_addr& ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn)
{
}

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr, addr.sin6_scope_id), port(ntohs(addr.sin6_port))
{
   assert(addr.sin6_family == AF_INET6);
}

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in*)paddr);
        return true;
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6*)paddr);
        return true;
    default:
        return false;
    }
}

CService::CService(const char *pszIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const char *pszIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, portDefault, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, portDefault, fAllowLookup))
        *this = ip;
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) && a.port == b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return static_cast<CNetAddr>(a) < static_cast<CNetAddr>(b) || (static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) && a.port < b.port);
}

/**
 * Obtain the IPv4/6 socket address this represents.
 *
 * @param[out] paddr The obtained socket address.
 * @param[in,out] addrlen The size, in bytes, of the address structure pointed
 *                        to by paddr. The value that's pointed to by this
 *                        parameter might change after calling this function if
 *                        the size of the corresponding address structure
 *                        changed.
 *
 * @returns Whether or not the operation was successful.
 */
bool CService::GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
    if (IsIPv6()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_scope_id = m_scope_id;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
    return false;
}

/**
 * @returns An identifier unique to this service's address and port number.
 */
std::vector<unsigned char> CService::GetKey() const
{
    auto key = GetAddrBytes();
    key.push_back(port / 0x100); // most significant byte of our port
    key.push_back(port & 0x0FF); // least significant byte of our port
    return key;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor() || IsI2P() || IsInternal()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

void CService::SetPort(unsigned short portIn)
{
    port = portIn;
}

CSubNet::CSubNet():
    valid(false)
{
    memset(netmask, 0, sizeof(netmask));
}

CSubNet::CSubNet(const CNetAddr& addr, uint8_t mask) : CSubNet()
{
    valid = (addr.IsIPv4() && mask <= ADDR_IPV4_SIZE * 8) ||
            (addr.IsIPv6() && mask <= ADDR_IPV6_SIZE * 8);
    if (!valid) {
        return;
    }

    assert(mask <= sizeof(netmask) * 8);

    network = addr;

    uint8_t n = mask;
    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        const uint8_t bits = n < 8 ? n : 8;
        netmask[i] = (uint8_t)((uint8_t)0xFF << (8 - bits)); // Set first bits.
        network.m_addr[i] &= netmask[i]; // Normalize network according to netmask.
        n -= bits;
    }
}

/**
 * @returns The number of 1-bits in the prefix of the specified subnet mask. If
 *          the specified subnet mask is not a valid one, -1.
 */
static inline int NetmaskBits(uint8_t x)
{
    switch(x) {
    case 0x00: return 0;
    case 0x80: return 1;
    case 0xc0: return 2;
    case 0xe0: return 3;
    case 0xf0: return 4;
    case 0xf8: return 5;
    case 0xfc: return 6;
    case 0xfe: return 7;
    case 0xff: return 8;
    default: return -1;
    }
}

CSubNet::CSubNet(const CNetAddr& addr, const CNetAddr& mask) : CSubNet()
{
    valid = (addr.IsIPv4() || addr.IsIPv6()) && addr.m_net == mask.m_net;
    if (!valid) {
        return;
    }
    // Check if `mask` contains 1-bits after 0-bits (which is an invalid netmask).
    bool zeros_found = false;
    for (auto b : mask.m_addr) {
        const int num_bits = NetmaskBits(b);
        if (num_bits == -1 || (zeros_found && num_bits != 0)) {
            valid = false;
            return;
        }
        if (num_bits < 8) {
            zeros_found = true;
        }
    }

    assert(mask.m_addr.size() <= sizeof(netmask));

    memcpy(netmask, mask.m_addr.data(), mask.m_addr.size());

    network = addr;

    // Normalize network according to netmask
    for (size_t x = 0; x < network.m_addr.size(); ++x) {
        network.m_addr[x] &= netmask[x];
    }
}

CSubNet::CSubNet(const CNetAddr& addr) : CSubNet()
{
    valid = addr.IsIPv4() || addr.IsIPv6();
    if (!valid) {
        return;
    }

    assert(addr.m_addr.size() <= sizeof(netmask));

    memset(netmask, 0xFF, addr.m_addr.size());

    network = addr;
}

/**
 * @returns True if this subnet is valid, the specified address is valid, and
 *          the specified address belongs in this subnet.
 */
bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid() || network.m_net != addr.m_net)
        return false;
    assert(network.m_addr.size() == addr.m_addr.size());
    for (size_t x = 0; x < addr.m_addr.size(); ++x) {
        if ((addr.m_addr[x] & netmask[x]) != network.m_addr[x]) {
            return false;
        }
    }
    return true;
}

std::string CSubNet::ToString() const
{
    assert(network.m_addr.size() <= sizeof(netmask));

    uint8_t cidr = 0;

    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        if (netmask[i] == 0x00) {
            break;
        }
        cidr += NetmaskBits(netmask[i]);
    }

    return network.ToString() + strprintf("/%u", cidr);
}

bool CSubNet::IsValid() const
{
    return valid;
}

bool operator==(const CSubNet& a, const CSubNet& b)
{
    return a.valid == b.valid && a.network == b.network && !memcmp(a.netmask, b.netmask, 16);
}

bool operator<(const CSubNet& a, const CSubNet& b)
{
    return (a.network < b.network || (a.network == b.network && memcmp(a.netmask, b.netmask, 16) < 0));
}

/**
 * Parse and resolve a specified subnet string into the appropriate internal
 * representation.
 *
 * @param strSubnet A string representation of a subnet of the form `network
 *                address [ "/", ( CIDR-style suffix | netmask ) ]`(e.g.
 *                `2001:db8::/32`, `192.0.2.0/255.255.255.0`, or `8.8.8.8`).
 * @param ret The resulting internal representation of a subnet.
 *
 * @returns Whether the operation succeeded or not.
 */
bool LookupSubNet(const std::string& strSubnet, CSubNet& ret)
{
    size_t slash = strSubnet.find_last_of('/');
    std::vector<CNetAddr> vIP;

    std::string strAddress = strSubnet.substr(0, slash);
    // TODO: Use LookupHost(const std::string&, CNetAddr&, bool) instead to just get
    //       one CNetAddr.
    if (LookupHost(strAddress, vIP, 1, false))
    {
        CNetAddr network = vIP[0];
        if (slash != strSubnet.npos)
        {
            std::string strNetmask = strSubnet.substr(slash + 1);
            uint8_t n;
            if (ParseUInt8(strNetmask, &n)) {
                // If valid number, assume CIDR variable-length subnet masking
                ret = CSubNet(network, n);
                return ret.IsValid();
            }
            else // If not a valid number, try full netmask syntax
            {
                // Never allow lookup for netmask
                if (LookupHost(strNetmask, vIP, 1, false)) {
                    ret = CSubNet(network, vIP[0]);
                    return ret.IsValid();
                }
            }
        }
        else
        {
            ret = CSubNet(network);
            return ret.IsValid();
        }
    }
    return false;
}

#ifdef _WIN32
std::string NetworkErrorString(int err)
{
    char buf[256];
    buf[0] = 0;
    if(FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, sizeof(buf), NULL))
    {
        return strprintf("%s (%d)", buf, err);
    }
    else
    {
        return strprintf("Unknown error (%d)", err);
    }
}
#else
std::string NetworkErrorString(int err)
{
    char buf[256];
    const char *s = buf;
    buf[0] = 0;
    /* Too bad there are two incompatible implementations of the
     * thread-safe strerror. */
#ifdef STRERROR_R_CHAR_P /* GNU variant can return a pointer outside the passed buffer */
    s = strerror_r(err, buf, sizeof(buf));
#else /* POSIX variant always returns message in buffer */
    if (strerror_r(err, buf, sizeof(buf)))
        buf[0] = 0;
#endif
    return strprintf("%s (%d)", s, err);
}
#endif

bool CloseSocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return false;
#ifdef _WIN32
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
    return ret != SOCKET_ERROR;
}

bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking)
{
    if (fNonBlocking) {
#ifdef _WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == SOCKET_ERROR) {
#endif
            CloseSocket(hSocket);
            return false;
        }
    } else {
#ifdef _WIN32
        u_long nZero = 0;
        if (ioctlsocket(hSocket, FIONBIO, &nZero) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags & ~O_NONBLOCK) == SOCKET_ERROR) {
#endif
            CloseSocket(hSocket);
            return false;
        }
    }

    return true;
}

bool SanityCheckASMap(const std::vector<bool>& asmap)
{
    return SanityCheckASMap(asmap, 128); // For IP address lookups, the input is 128 bits
}
