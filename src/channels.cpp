#include "channels.h"

using namespace SSH;

class Session_Channel : public SSH::IChannel
{
public:
  Session_Channel(UINT32 id, TOnEventFunc callback)
    : IChannel(id, ChannelTypes::Session, callback)
  {
  }

  virtual ~Session_Channel()
  {
  }
};

TChannel Channel::Create(ChannelTypes type, TChannelID id, TOnEventFunc callback)
{
  switch (type)
  {
    case ChannelTypes::Session: return std::make_shared<Session_Channel>(id, callback);
    default: return nullptr;
  }
}

std::string Channel::ChannelTypeToString(ChannelTypes type)
{
  switch (type)
  {
    case ChannelTypes::Session: return "session";
    default: return "";
  }
}

/*
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
*/
