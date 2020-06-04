#ifndef __SSH_IMPL_H__
#define __SSH_IMPL_H__

#include "ssh.h"

namespace SSH
{
  class Client::Impl
  {
  protected:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TCtx mCtx;
    State mState;

  public:
    Impl(ClientOptions options, TCtx ctx);
    ~Impl();

    TResult Send(const char* pBuf, const int bufLen);

    void Connect(const char* pszUser);
    void Disconnect();

    State GetState() const { return mState; }
  };
}

#endif //~__SSH_IMPL_H__
