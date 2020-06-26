#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
#include <vector>
#include <memory>

namespace SSH
{
  enum class ChannelTypes
  {
    Null,
    Session,
  };

  class IChannel
  {
  public:
    IChannel() = default;
    virtual ~IChannel() = default;

    virtual UINT32 ID() const = 0;
    virtual ChannelTypes Type() const = 0;
  };

  using TChannel = std::shared_ptr<IChannel>;

  namespace Channels
  {
    TChannel Open(ChannelTypes type);
  }
}

#endif //~__CHANNELS_H__
