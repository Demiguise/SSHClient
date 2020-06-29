#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
#include "packets.h"
#include <string>
#include <vector>
#include <memory>

namespace SSH
{
  class IChannel
  {
  public:
    IChannel() = default;
    virtual ~IChannel() = default;

    virtual TChannelID ID() const = 0;
    virtual ChannelTypes Type() const = 0;
    virtual void OnEvent(ChannelEvent event, const Byte* pBuf, const int bufLen) = 0;
  };

  using TChannel = std::shared_ptr<IChannel>;

  class ChannelManager
  {
  private:
    TChannelID mNextID = 1;

    using TChannelVec = std::vector<TChannel>;
    TChannelVec mChannels;

    std::string ChannelTypeToString(ChannelTypes type);

    TPacket CreateOpenChannelRequest(TChannel channel, PacketStore& store);

    TChannel GetChannel(TChannelID channelID);
  public:
    ChannelManager() = default;
    ~ChannelManager() = default;

    std::pair<TChannelID, TPacket> Open(ChannelTypes type, TOnEventFunc callback, PacketStore& store);
    bool Close(TChannelID channelID, PacketStore& store);

    //Returns true if handled
    bool HandlePacket(TPacket pPacket);
  };
}

#endif //~__CHANNELS_H__
