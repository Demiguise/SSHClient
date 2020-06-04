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

  using TCtx = std::weak_ptr<void>;
  using TResult = std::optional<int>;

  using TSendFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TOnRecvFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;

#ifdef __DEBUG
  using TLogFunc = std::function<TResult (const char* pszLogString)>;
#endif //~__DEBUG

  struct ClientOptions
  {
    TSendFunc send;   //Function for how the SSH Client will SEND data into the socket
    TRecvFunc recv;   //Function for how the SSH Client will RECEIVE data from a socket
    TOnRecvFunc onRecv; //Function for when the SSH Client has received data for your application
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

#ifdef __DEBUG
    void SetLogFunc(TLogFunc func);
#endif //~__DEBUG
  };
}

#endif //~__SSH_H__
