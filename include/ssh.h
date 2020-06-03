#ifndef __SSH_H__
#define __SSH_H__

#include <functional>
#include <memory>
#include <optional>

namespace SSH
{
  using TCtx = std::weak_ptr<void>;
  using TSendFunc = std::function<void (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<void (TCtx ctx, const char *pBuf, const int bufLen)>;

  class Client
  {
  private:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TCtx mCtx;

  public:
    //Base constructor
    Client(TSendFunc sendFunc, TRecvFunc recvFunc, TCtx ctx);

    void Send(const char* pBuf, const int bufLen);
    void Recv(const char* pBuf, const int bufLen);
  };
}

#endif //~__SSH_H__
