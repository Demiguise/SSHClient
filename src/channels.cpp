#include "channels.h"

using namespace SSH;

class Channel : public IChannel
{
private:
  UINT32 mChannelId;
  ChannelTypes mChannelType;

public:
  Channel(ChannelTypes type, UINT32 id)
    : mChannelId(id)
    , mChannelType(type)
  {
  }

  virtual ~Channel()
  {
  }

  virtual TChannelID ID() const override { return mChannelId; }
  virtual ChannelTypes Type() const override { return mChannelType; }
};

TChannelID ChannelManager::Open(ChannelTypes type, TOnRecvFunc callback)
{
  TChannel newChannel = std::make_shared<Channel>(type, mNextID++);

  return newChannel->ID();
}

bool ChannelManager::Close(TChannelID)
{
  return false;
}
