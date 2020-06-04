#include "ssh_impl.h"

using namespace SSH;

Client::Impl::Impl(ClientOptions options, TCtx ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.recv)
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

TResult Client::Impl::Recv(const char* pBuf, const int bufLen)
{
  return mRecvFunc(mCtx, pBuf, bufLen);
}

void Client::Impl::Connect(const char* pszUser)
{
  //Set initial state to disconnected while we are attempting to make our connection.
  mState = State::Disconnected;
}

void Client::Impl::Disconnect()
{
  mState = State::Disconnected;
}
