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

  using TCtx = std::weak_ptr<void>;
  using TResult = std::optional<int>;

  using TSendFunc = std::function<TResult (TCtx ctx, const Byte* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<TResult (TCtx ctx, Byte* pBuf, const int bufLen)>;
  using TOnRecvFunc = std::function<TResult (TCtx ctx, const Byte* pBuf, const int bufLen)>;
  using TLogFunc = std::function<void (const char* pszLogString)>;

  using TOnConnectFunc = std::function<void (Client* pClient)>;

  using TOnAuthFunc = std::function<TResult (TCtx ctx, UserAuthMethod, Byte* pBuf, const int bufLen)>;
  using TAuthMethods = std::queue<UserAuthMethod>;

  struct ClientOptions
  {
    TSendFunc send;   //Function for how the SSH Client will SEND data into the socket
    TRecvFunc recv;   //Function for how the SSH Client will RECEIVE data from a socket
    TOnAuthFunc onAuth; //Function for when the SSH Client requests private data for authentication
    TAuthMethods authMethods; //Authentication methods available to the SSH client

    TOnConnectFunc onConnect; //Function for when the SSH client has successully connected to the remote
    std::string userName;

    TLogFunc log;
    LogLevel logLevel;
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

    TResult Send(const Byte* pBuf, const int bufLen);

    void Connect();
    void Disconnect();

    void OpenChannel(ChannelTypes type, TOnRecvFunc callback)

    State GetState() const;
  };

  const char* StateToString(State state);

  void Init(); //Called ONCE before any usage
  void Cleanup();
}

#endif //~__SSH_H__
