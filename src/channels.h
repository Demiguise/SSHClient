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

    virtual UINT32 ID() const = 0;
    virtual ChannelTypes Type() const = 0;
  };

  using TChannel = std::shared_ptr<IChannel>;

  class ChannelManager
  {
    UINT32 mNextID = 0;
  public:
    ChannelManager() = default;
    ~ChannelManager() = default;

    TChannel Open(ChannelTypes type);
  };
}

#endif //~__CHANNELS_H__
