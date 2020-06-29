#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
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
    TChannelID mNextID = 0;
  public:
    ChannelManager() = default;
    ~ChannelManager() = default;

    TChannelID Open(ChannelTypes type, TOnRecvFunc callback);
    bool Close(TChannelID channelID);
  };
}

#endif //~__CHANNELS_H__
