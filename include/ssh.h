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
    Authenticating,
    Connected,
  };

  using TCtx = std::weak_ptr<void>;
  using TResult = std::optional<int>;

  using TSendFunc = std::function<TResult (TCtx ctx, const char* pBuf, const int bufLen)>;
  using TRecvFunc = std::function<TResult (TCtx ctx, const char *pBuf, const int bufLen)>;

  struct ClientOptions
  {
    TSendFunc send;
    TRecvFunc onRecv;
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
