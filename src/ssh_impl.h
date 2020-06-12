#ifndef __SSH_IMPL_H__
#define __SSH_IMPL_H__

#include "ssh.h"
#include "name-list.h"
#include <queue>

namespace SSH
{
  enum class ConStage
  {
    Null, //Empty stage

    //Handshake Stages
    SentClientID,
    ReceivedServerID,

    SendClientKEXInit,
    SentClientKEXInit,
    ReceivedServerKEXInit,

    SentClientDHInit,
    ReceivedNewKeys,
    SentServiceRequest,

    //Authentication Stages

    //Channel Stages
  };

  class IPacket;

  struct ListPairs
  {
    NameList mClientToServer;
    NameList mServerToClient;
  };

  struct KEXData
  {
    struct
    {
      NameList mKex;
      NameList mServerHost;
      ListPairs mEncryption;
      ListPairs mMAC;
      ListPairs mCompression;
      ListPairs mLanguages;
    } mAlgorithms;
  };

  class Packet;

  class Client::Impl
  {
  private:
    static const int sMaxLogLength = 256;
    using TPacketQueue = std::queue<std::shared_ptr<Packet>>;

  protected:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TOnRecvFunc mOnRecvFunc;

    TCtx mCtx;
    State mState;
    ConStage mStage;

    TLogFunc mLogFunc;
    LogLevel mLogLevel;

    TPacketQueue mRecvQueue;
    TPacketQueue mSendQueue;

    KEXData mKex;

    UINT32 mSequenceNumber;

    void Log(LogLevel level, std::string frmt, ...);
    void LogBuffer(LogLevel level, std::string bufferName, const Byte* pBuf, const int bufLen);

    void HandleData(const Byte* pBuf, const int bufLen);

    //Returns number of bytes consumed
    int ParseNameList(NameList& list, const Byte* pBuf);

    bool HandleServerIdent(const Byte* pBuf, const int bufLen);

    void PerformKEX(const Byte* pBuf, const int bufLen);
    void SendClientKEXInit();

    TResult Send(std::shared_ptr<Packet> pPacket);

  public:
    Impl(ClientOptions& options, TCtx& ctx);
    ~Impl();

    TResult Send(const Byte* pBuf, const int bufLen);
    void Queue(std::shared_ptr<Packet> pPacket);

    void Poll();

    void Connect(const std::string pszUser);
    void Disconnect();

    State GetState() const { return mState; }
  };
}

#endif //~__SSH_IMPL_H__
