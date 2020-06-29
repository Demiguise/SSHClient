#include "channels.h"

using namespace SSH;

class SSH::IChannel
{
private:
  UINT32 mChannelId;
  ChannelTypes mChannelType;
  TOnEventFunc mOnEvent;

public:
  IChannel(UINT32 id, ChannelTypes type, TOnEventFunc callback)
    : mChannelId(id)
    , mChannelType(ChannelTypes::Session)
    , mOnEvent(callback)
  {}

  virtual ~IChannel() = default;

  TChannelID ID() const
  {
    return mChannelId;
  }

  ChannelTypes Type() const
  {
    return mChannelType;
  }

  void OnEvent(ChannelEvent event, const Byte* pBuf, const int bufLen)
  {
    mOnEvent(event, pBuf, bufLen);
  }
};

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

ChannelManager::TChannel ChannelManager::GetChannel(TChannelID channelID)
{
  auto iter = std::find_if(mChannels.begin(), mChannels.end(), [&](TChannel channel){
    return (channel->ID() == channelID);
  });

  return (iter == mChannels.end()) ? nullptr : *iter;
}

std::pair<TChannelID, TPacket> ChannelManager::Open(ChannelTypes type, TOnEventFunc callback, PacketStore& store)
{
  if (type == ChannelTypes::Null)
  {
    return {0, nullptr};
  }

  TChannel newChannel = std::make_shared<Session_Channel>(mNextID++, callback);
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

bool ChannelManager::HandlePacket(TPacket pPacket)
{
  Byte msgId;
  pPacket->Peek(msgId);

  switch (msgId)
  {
    case SSH_MSG::CHANNEL_OPEN_CONFIRMATION:
    {
      //Channel opened!
      TChannelID receipientID = 0;
      pPacket->Read(msgId);
      pPacket->Read(receipientID);

      TChannel channel = GetChannel(receipientID);
      if (channel == nullptr)
      {
        return false;
      }

      channel->OnEvent(ChannelEvent::Opened, nullptr, 0);
    }
    break;
    default:
    {
      return false;
    }
  }

  return false;
}
