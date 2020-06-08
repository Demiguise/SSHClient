#ifndef __SSH_IMPL_H__
#define __SSH_IMPL_H__

#include "ssh.h"
#include <queue>

namespace SSH
{
  enum class Stage
  {
    Null, //Empty stage

    //Handshake Stages
    ServerIdent,
    ServerKEX,

    //Authentication Stages

    //Channel Stages
  };

  class IPacket;

  class Client::Impl
  {
  private:
    static const int sMaxLogLength = 256;
    using TPacketQueue = std::queue<IPacket*>;

  protected:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TOnRecvFunc mOnRecvFunc;

    TCtx mCtx;
    State mState;
    Stage mStage;

    TLogFunc mLogFunc;
    LogLevel mLogLevel;

    TPacketQueue mQueue;

    void Log(LogLevel level, std::string frmt, ...);
    void LogBuffer(LogLevel level, std::string bufferName, const Byte* pBuf, const int bufLen);

    void HandleData(const Byte* pBuf, const int bufLen);

    void HandleServerIdent(const Byte* pBuf, const int bufLen);
    void PerformKEX(const Byte* pBuf, const int bufLen);

  public:
    Impl(ClientOptions options, TCtx ctx);
    ~Impl();

    TResult Send(const Byte* pBuf, const int bufLen);

    void Poll();

    void Connect(const std::string pszUser);
    void Disconnect();

    State GetState() const { return mState; }
  };
}

#endif //~__SSH_IMPL_H__
