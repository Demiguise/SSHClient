#ifndef __SSH_IMPL_H__
#define __SSH_IMPL_H__

#include "ssh.h"
#include "name-list.h"
#include "packets.h"
#include "kex/kex.h"
#include "crypto/crypto.h"
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
    ReceivedServerDHReply,
    ReceivedNewKeys,
    SentNewKeys,
    SentServiceRequest,

    //Authentication Stages
    ReceivedServiceAccept,
    AttemptingUserAuth,
    UserLoggedIn

    //Channel Stage
  };

  std::string StageToString(ConStage stage);
  std::string AuthMethodToString(UserAuthMethod method);

  class IPacket;

  class Client::Impl
  {
  private:
    static const int sMaxLogLength = 256;
    using TPacketQueue = std::queue<TPacket>;

    enum class UserAuthResponse
    {
      Success, // A userauth method responded was successful, the user is now logged in
      Failure, // Failure occurs when ALL available authentication end with failure
      Retry,   // More userauth methods are available
      Banner,  // A special message that may come after userauth begins
    };

  protected:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TOnRecvFunc mOnRecvFunc;
    TOnAuthFunc mOnAuthFunc;

    TAuthMethods mAuthMethods;
    UserAuthMethod mActiveAuthMethod;
    std::string mUserName;

    TCtx mCtx;
    State mState;
    ConStage mStage;

    TLogFunc mLogFunc;
    LogLevel mLogLevel;

    TPacketQueue mRecvQueue;
    TPacketQueue mSendQueue;

    KEXData mServerKex;
    KEXData mClientKex;
    TKEXHandler mKEXHandler;

    UINT32 mIncomingSequenceNumber;
    UINT32 mOutgoingSequenceNumber;

    PacketStore mPacketStore;

    //These are the Server to Client keys
    struct
    {
      Key mIV;
      Key mEnc;
      Key mMac;
    } mRemoteKeys;

    //These are the Client to Server keys
    struct
    {
      Key mIV;
      Key mEnc;
      Key mMac;
    } mLocalKeys;

    Key mSessionID;

    void Log(LogLevel level, std::string frmt, ...);
    void LogBuffer(LogLevel level, std::string bufferName, const Byte* pBuf, const int bufLen);
    void SetStage(ConStage newStage);

    void HandleData(const Byte* pBuf, const int bufLen);
    /*
      Consumes as many bytes as possible from the buffer to form packets.
      Returns number of bytes consumed.
    */
    int ConsumeBuffer(const Byte* pBuf, const int bufLen);

    //Returns number of bytes consumed
    int ParseNameList(NameList& list, const Byte* pBuf);

    bool ReceiveServerIdent(const Byte* pBuf, const int bufLen);

    //Transport Stages
    void SendClientKEXInit();
    bool ReceiveServerKEXInit(TPacket pPacket);
    void SendClientDHInit();
    bool ReceiveServerDHReply(TPacket pPacket);
    bool ReceiveNewKeys(TPacket pPacket);
    void SendNewKeys();

    //Authentication Stages
    void SendServiceRequest();
    bool ReceiveServiceAccept(TPacket pPacket);
    void SendUserAuthRequest(UserAuthMethod method);
    UserAuthResponse ReceiveUserAuth(TPacket pPacket);

    TResult Send(std::shared_ptr<Packet> pPacket);

  public:
    Impl(ClientOptions& options, TCtx& ctx);
    ~Impl();

    TResult Send(const Byte* pBuf, const int bufLen);
    void Queue(std::shared_ptr<Packet> pPacket);

    void Poll();

    void Connect(const std::string user);
    void Disconnect();

    State GetState() const { return mState; }
  };
}

#endif //~__SSH_IMPL_H__
