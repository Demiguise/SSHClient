#ifndef __SSH_H__
#define __SSH_H__

#include <functional>
#include <memory>
#include <optional>
#include <queue>

using UINT32 = uint32_t;

namespace SSH
{
  using Byte = unsigned char;

  enum class State
  {
    Idle,
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
  };

  enum class UserAuthMethod
  {
    None,
    Password,
  };

  enum class ChannelEvent
  {
    Opened,
    Data,
    Closed,
  }

  enum class ChannelTypes
  {
    Null,
    Session,
  };

  enum LogLevel
  {
    Error   = 0,
    Warning = 1,
    Info    = 2,
    Debug   = 3,
  };

  class Client;

  using TCtx = std::weak_ptr<void>;
  using TResult = std::optional<int>;

  using TSendFunc = std::function<TResult (TCtx ctx, const Byte* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<TResult (TCtx ctx, Byte* pBuf, const int bufLen)>;
  using TOnRecvFunc = std::function<TResult (TCtx ctx, ChannelEvent event, const Byte* pBuf, const int bufLen)>;
  using TLogFunc = std::function<void (const char* pszLogString)>;

  using TOnConnectFunc = std::function<void (Client* pClient)>;

  using TOnAuthFunc = std::function<TResult (TCtx ctx, UserAuthMethod, Byte* pBuf, const int bufLen)>;
  using TAuthMethods = std::queue<UserAuthMethod>;

  using TChannelID = UINT32;

  struct ClientOptions
  {
    TSendFunc mSend;   //Function for how the SSH Client will SEND data into the socket
    TRecvFunc mRecv;   //Function for how the SSH Client will RECEIVE data from a socket
    TOnAuthFunc mOnAuth; //Function for when the SSH Client requests private data for authentication
    TAuthMethods mAuthMethods; //Authentication methods available to the SSH client

    TOnConnectFunc mOnConnect; //Function for when the SSH client has successully connected to the remote
    std::string mUserName;

    TLogFunc mLogFunc;
    LogLevel mLogLevel;
  };

  class Client
  {
  private:
    /*
      Seperate implementation details away from the client interface.
      Interface API can stay solid while implemenation details change underneath.
    */
    class Impl;
    std::unique_ptr<Impl> mImpl;

  public:
    Client(ClientOptions& options, TCtx& ctx);
    ~Client();

    void Connect();
    void Disconnect();

    /*
      OpenChannel does not mean that the remote successfully opened a new
      channel.
      The callback will receive an event once the channel has been opened.
    */
    TChannelID OpenChannel(ChannelTypes type, TOnRecvFunc callback);
    bool CloseChannel(TChannelID channelID);

    TResult Send(TChannelID channelID, const Byte* pBuf, const int bufLen);

    State GetState() const;
  };

  const char* StateToString(State state);

  void Init(); //Called ONCE before any usage
  void Cleanup();
}

#endif //~__SSH_H__
