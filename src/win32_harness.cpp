#pragma comment(lib,"Ws2_32.lib")

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#include "ssh.h"

#include <memory>

class WinSock
{
private:
    SOCKET mSock;
public:
    WinSock()
        : mSock(INVALID_SOCKET)
    {}

    ~WinSock()
    {
        if (mSock != INVALID_SOCKET)
        {
            closesocket(mSock);
        }
    }

    bool Connect(const char* pszAddress, const short port)
    {
        mSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (mSock == INVALID_SOCKET)
        {
            printf("Socket could not be created.\n");
            return false;
        }

        printf("Socket created!\n");

        SOCKADDR_IN srvInfo;
        srvInfo.sin_family = AF_INET;
        srvInfo.sin_port = htons(port);
        inet_pton(AF_INET, pszAddress, &srvInfo.sin_addr);

        int result = connect(mSock, (SOCKADDR*)&srvInfo, sizeof(srvInfo));
        if (result == SOCKET_ERROR)
        {
            printf("Failed to connect socket to remote server: %ld\n", WSAGetLastError());
            return false;
        }

        return true;
    }

    SOCKET Get() { return mSock; }
};

using TSharedSock = std::shared_ptr<WinSock>;

int main()
{
    WSADATA wsaData = { 0 };
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

    TSharedSock pSock = std::make_shared<WinSock>();
    pSock->Connect("10.7.0.10", 22);

    SSH::TSendFunc sendFunc = [](SSH::TCtx ctx, const SSH::Byte* pBuf, const int bufLen) -> SSH::TResult {
        WinSock* pSock = (WinSock*)(ctx.lock().get());
        int result = send(pSock->Get(), (char*)pBuf, bufLen, 0);
        if (result == SOCKET_ERROR)
        {
            printf("Failed to send data: %d\n", WSAGetLastError());
            return {};
        }

        return result;
    };

    SSH::TRecvFunc recvFunc = [](SSH::TCtx ctx, SSH::Byte* pBuf, const UINT64 bufLen) -> SSH::TResult {
        WinSock* pSock = (WinSock*)(ctx.lock().get());
        int result = recv(pSock->Get(), (char*)pBuf, bufLen, 0);
        if (result == SOCKET_ERROR)
        {
            printf("Failed to send data: %d\n", WSAGetLastError());
            return {};
        }

        return result;
    };

    SSH::TOnRecvFunc onRecvFunc = [](SSH::TCtx ctx, const SSH::Byte* pBuf, const UINT64 bufLen) -> SSH::TResult {
        return {};
    };

    SSH::TLogFunc logFunc = [](const char* pszLogString) {
        printf("SSH Client: %s\n", pszLogString);
    };

    SSH::TCtx sockCtx = pSock;

    SSH::ClientOptions opts;
    opts.send = sendFunc;
    opts.recv = recvFunc;
    opts.onRecv = onRecvFunc;
    opts.log = logFunc;
    opts.logLevel = SSH::LogLevel::Debug;

    auto client = SSH::Client(opts, sockCtx);
    client.Connect("pi");

    while (true)
    {
    }

    WSACleanup();

    return 0;
}

