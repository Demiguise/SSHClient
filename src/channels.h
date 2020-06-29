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

  class IChannel
  {
  private:
    UINT32 mChannelId;
    ChannelTypes mChannelType;
    TOnEventFunc mOnEvent;

  public:
    IChannel(UINT32 id, ChannelTypes type, TOnEventFunc callback)
        : mChannelId(id), mChannelType(ChannelTypes::Session), mOnEvent(callback)
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
  };

  using TChannel = std::shared_ptr<IChannel>;
  using TChannelVec = std::vector<TChannel>;

  namespace Channel
  {
    TChannel Create(ChannelTypes type, TChannelID id, TOnEventFunc callback);
    std::string ChannelTypeToString(ChannelTypes type);
  }
}

#endif //~__CHANNELS_H__
