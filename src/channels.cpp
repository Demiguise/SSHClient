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

  virtual TPacket CreateOpenPacket(PacketStore& store) override
  {
    std::string channelType = Channel::ChannelTypeToString(mChannelType);
    UINT32 packetLen =  sizeof(Byte) +          //SSH_MSG
                        sizeof(UINT32) +        //Channel type field length
                        channelType.length() +  //Channel type
                        sizeof(UINT32) +        //Sender Channel
                        sizeof(UINT32) +        //Initial window size
                        sizeof(UINT32);         //Maximum packet size

    TPacket newPacket = store.Create(packetLen, PacketType::Write);

    newPacket->Write(SSH_MSG::CHANNEL_OPEN);
    newPacket->Write(channelType);
    newPacket->Write(mChannelId);
    newPacket->Write(0);
    newPacket->Write(0);

    return newPacket;
  }

  virtual TPacket CreateClosePacket(PacketStore& store) override
  {
    return nullptr;
  }

  virtual bool HandleData(TPacket pPacket) override
  {
    return true;
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
