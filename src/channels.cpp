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

TChannelID ChannelManager::Open(ChannelTypes type, TOnRecvFunc callback, PacketStore& store)
{
  TChannel newChannel = std::make_shared<Channel>(type, mNextID++);
  if (newChannel == nullptr)
  {
    return 0;
  }

  mChannels.push_back(newChannel);

  return newChannel->ID();
}

bool ChannelManager::Close(TChannelID channelID, PacketStore& store)
{
  auto iter = std::find_if(mChannels.begin(), mChannels.end(), [&](TChannel channel){
    return (channel->ID() == channelID);
  });

  if (iter == mChannels.end())
  {
    return false;
  }

  mChannels.erase(iter);
  return true;
}
