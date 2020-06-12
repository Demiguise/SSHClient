#include "ssh.h"
#include "ssh_impl.h"

#include <wolfssl/wolfcrypt/wc_port.h>

using namespace SSH;

const char* SSH::StateToString(State state)
{
  switch (state)
  {
    case State::Idle: return "Idle";
    case State::Disconnected: return "Disconnected";
    case State::Connecting: return "Connecting";
    case State::Authenticating: return "Authenticating";
    case State::Connected: return "Connected";
    default: return "Unknown";
  }
}

static bool gInitialised = false;

void SSH::Init()
{
  if (gInitialised)
  {
    return;
  }

  wolfCrypt_Init();

  gInitialised = true;
}

void SSH::Cleanup()
{
  if (!gInitialised)
  {
    return;
  }

  wolfCrypt_Cleanup();

  gInitialised = false;
}

Client::Client(ClientOptions& options, TCtx& ctx)
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
