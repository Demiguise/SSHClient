#include "ssh.h"
#include "ssh_impl.h"

using namespace SSH;

Client::Client(ClientOptions options, TCtx ctx)
{
  //TODO: Handle NullPtr
  mImpl = std::make_unique<Client::Impl>(options, ctx);
}

Client::~Client()
{
  mImpl.reset();
}

TResult Client::Send(const Byte* pBuf, const int bufLen)
{
  return mImpl->Send(pBuf, bufLen);
}

void Client::Connect(const std::string pszUser)
{
  mImpl->Connect(pszUser);
}

void Client::Disconnect()
{
  mImpl->Disconnect();
}

State Client::GetState() const
{
  return mImpl->GetState();
}
