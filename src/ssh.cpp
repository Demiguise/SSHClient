#include "ssh.h"
#include "ssh_impl.h"

using namespace SSH;

Client::Client(ClientOptions options, TCtx ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.recv)
  , mCtx(ctx)
  , mState(State::Idle)
{
  mImpl = std::make_unique<ClientImpl>();
}

Client::~Client()
{
  mImpl.reset();
}

TResult Client::Send(const char* pBuf, const int bufLen)
{
  return mSendFunc(mCtx, pBuf, bufLen);
}

TResult Client::Recv(const char* pBuf, const int bufLen)
{
  return mRecvFunc(mCtx, pBuf, bufLen);
}

void Client::Connect(const char* pszUser)
{
  //Set initial state to disconnected while we are attempting to make our connection.
  mState = State::Disconnected;
}

void Client::Disconnect()
{
  mState = State::Disconnected;
}
