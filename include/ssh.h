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
    TRecvFunc recv;
  };

  class Client
  {
  private:
    TSendFunc mSendFunc;
    TRecvFunc mRecvFunc;
    TCtx mCtx;
    State mState;

    /*
      Seperate implementation details away from the client interface.
      Interface API can stay solid while implemenation details change underneath.
    */
    class ClientImpl;
    friend class ClientImpl;
    std::unique_ptr<ClientImpl> mImpl;

  public:
    Client(ClientOptions options, TCtx ctx);
    ~Client();

    TResult Send(const char* pBuf, const int bufLen);
    TResult Recv(const char* pBuf, const int bufLen);

    void Connect(const char* pszUser);
    void Disconnect();

    State GetState() const { return mState; }
  };
}

#endif //~__SSH_H__
