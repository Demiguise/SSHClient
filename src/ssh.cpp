#include "ssh.h"
#include "ssh_impl.h"

#define WOLFCRYPT_ONLY
#include <IDE/WIN10/user_settings.h>
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
  mImpl = std::make_unique<Client::Impl>(options, ctx, this);
}

Client::~Client()
{
  mImpl.reset();
}

void Client::Connect()
{
  mImpl->Connect();
}

void Client::Disconnect()
{
  mImpl->Disconnect();
}

TChannelID Client::OpenChannel(ChannelTypes type, TOnEventFunc callback)
{
  return mImpl->OpenChannel(type, callback);
}

bool Client::CloseChannel(TChannelID channelID)
{
  return mImpl->CloseChannel(channelID);
}

TResult Client::Send(TChannelID channelID, const Byte* pBuf, const int bufLen)
{
  return mImpl->Send(channelID, pBuf, bufLen);
}

State Client::GetState() const
{
  return mImpl->GetState();
}
