#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
#include "packets.h"
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
  };

  using TChannel = std::shared_ptr<IChannel>;

  class ChannelManager
  {
  private:
    TChannelID mNextID = 1;

    using TChannelVec = std::vector<TChannel>;
    TChannelVec mChannels;

    TPacket CreateOpenChannelRequest(TChannel channel, PacketStore& store);
  public:
    ChannelManager() = default;
    ~ChannelManager() = default;

    std::pair<TChannelID, TPacket> Open(ChannelTypes type, TOnRecvFunc callback, PacketStore& store);
    bool Close(TChannelID channelID, PacketStore& store);
  };
}

#endif //~__CHANNELS_H__
