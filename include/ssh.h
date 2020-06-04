#ifndef __SSH_H__
#define __SSH_H__

#include <functional>
#include <memory>
#include <optional>

namespace SSH
{
  enum class State
  {
    Idle,
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
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

  using TSendFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<TResult (TCtx ctx, unsigned char* pBuf, const int bufLen)>;
  using TOnRecvFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TLogFunc = std::function<void (const char* pszLogString)>;

  struct ClientOptions
  {
    TSendFunc send;   //Function for how the SSH Client will SEND data into the socket
    TRecvFunc recv;   //Function for how the SSH Client will RECEIVE data from a socket
    TOnRecvFunc onRecv; //Function for when the SSH Client has received data for your application

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
    Client(ClientOptions options, TCtx ctx);
    ~Client();

    TResult Send(const char* pBuf, const int bufLen);

    void Connect(const char* pszUser);
    void Disconnect();

    State GetState() const;
  };
}

#endif //~__SSH_H__
