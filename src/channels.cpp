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

std::string ChannelManager::ChannelTypeToString(ChannelTypes type)
{
  switch (type)
  {
    case ChannelTypes::Session: return "session";
    default: return "";
  }
}

TPacket ChannelManager::CreateOpenChannelRequest(TChannel channel, PacketStore& store)
{
  ChannelTypes type = channel->Type();
  std::string channelType = ChannelTypeToString(type);
  UINT32 packetLen =  sizeof(Byte) +          //SSH_MSG
                      sizeof(UINT32) +        //Channel type field length
                      channelType.length() +  //Channel type
                      sizeof(UINT32) +        //Sender Channel
                      sizeof(UINT32) +        //Initial window size
                      sizeof(UINT32);         //Maximum packet size

  TPacket newPacket = nullptr;
  switch (type)
  {
    case ChannelTypes::Session:
    {
      newPacket = store.Create(packetLen, PacketType::Write);

      newPacket->Write(SSH_MSG::CHANNEL_OPEN);
      newPacket->Write(channelType);
      newPacket->Write(channel->ID());
      newPacket->Write(0);
      newPacket->Write(0);

      break;
    }
    default: break;
  }

  return newPacket;
}

std::pair<TChannelID, TPacket> ChannelManager::Open(ChannelTypes type, TOnRecvFunc callback, PacketStore& store)
{
  if (type == ChannelTypes::Null)
  {
    return {0, nullptr};
  }

  TChannel newChannel = std::make_shared<Channel>(type, mNextID++);
  if (newChannel == nullptr)
  {
    return {0, nullptr};
  }

  TPacket openPacket = CreateOpenChannelRequest(newChannel, store);
  if (openPacket == nullptr)
  {
    return {0, nullptr};
  }

  mChannels.push_back(newChannel);

  return {newChannel->ID(), openPacket};
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
