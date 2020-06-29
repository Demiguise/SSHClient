#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
#include "packets.h"
#include <string>
#include <vector>
#include <memory>

namespace SSH
{
  class IChannel;

  class ChannelManager
  {
  private:
    using TChannel = std::shared_ptr<IChannel>;
    using TChannelVec = std::vector<TChannel>;

    TChannelID mNextID = 1;
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
