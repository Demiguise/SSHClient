#include "ssh_impl.h"

#include <future>
#include <array>
#include <cstring> //Memset_s

using namespace SSH;

template<std::size_t size>
class SecureBuffer
{
private:
  std::array<char, size> mArr;
public:
  SecureBuffer()
  {}

  ~SecureBuffer()
  {
    //TODO: This NEEDS to be secure
    memset(mArr.data(), 0, size);
  }

  const char* Buffer() { return mArr.data(); }
  size_t Length() { return size; }
};

Client::Impl::Impl(ClientOptions options, TCtx ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.onRecv)
  , mCtx(ctx)
  , mState(State::Idle)
{
}

Client::Impl::~Impl()
{
}

TResult Client::Impl::Send(const char* pBuf, const int bufLen)
{
  return mSendFunc(mCtx, pBuf, bufLen);
}

void Client::Impl::Poll()
{
  if (mState == State::Disconnected)
  {
    //End the polling async if we're disconnected
    return;
  }

  SecureBuffer<1024> buf;
  auto recievedBytes = mRecvFunc(mCtx, buf.Buffer(), buf.Length());
}

void Client::Impl::Connect(const char* pszUser)
{
  mState = State::Connecting;

  auto fut = std::async(&Impl::Poll, this);
}

void Client::Impl::Disconnect()
{
  mState = State::Disconnected;
}
