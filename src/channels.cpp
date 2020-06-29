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
    newPacket->Write(1024);
    newPacket->Write(1024);

    return newPacket;
  }

  virtual TPacket CreateClosePacket(PacketStore& store) override
  {
    return nullptr;
  }

  virtual TPacket PrepareSend(const Byte* pBuf, const int bufLen, PacketStore& store) override
  {
    UINT32 packetLen =  sizeof(Byte) +    //SSH_MSG
                        sizeof(UINT32) +  //Recipient channel
                        sizeof(UINT32) +  //Data length field
                        bufLen;           //Data

    TPacket newPacket = store.Create(packetLen, PacketType::Write);

    newPacket->Write(SSH_MSG::CHANNEL_DATA);
    newPacket->Write(mChannelId);
    newPacket->Write(pBuf, bufLen);

    return newPacket;
  }

  virtual bool HandleData(Byte msgId, TPacket pPacket) override
  {
    switch (msgId)
    {
      case SSH_MSG::CHANNEL_OPEN_CONFIRMATION:
      {
        mState = ChannelState::Open;
        mOnEvent(ChannelEvent::Opened, nullptr, 0);

        break;
      }
      case SSH_MSG::CHANNEL_DATA:
      {
        TByteString data;
        pPacket->Read(data);

        mOnEvent(ChannelEvent::Data, data.data(), data.size());
        break;
      }
    }

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
