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
    TOnRecvFunc mOnRecvFunc;

    TCtx mCtx;
    State mState;

#ifdef __DEBUG
    TLogFunc mLogFunc;
#endif //~__DEBUG

  public:
    Impl(ClientOptions options, TCtx ctx);
    ~Impl();

    TResult Send(const char* pBuf, const int bufLen);

    void Poll();

    void Connect(const char* pszUser);
    void Disconnect();

    State GetState() const { return mState; }

#ifdef __DEBUG
    void SetLogFunc(TLogFunc func) { mLogFunc = func; }
#endif //~__DEBUG
  };
}

#endif //~__SSH_IMPL_H__
