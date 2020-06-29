#ifndef __CHANNELS_H__
#define __CHANNELS_H__

#include "ssh.h"
#include "packets.h"
#include <string>
#include <vector>
#include <memory>

namespace SSH
{
  enum class ChannelState
  {
    Opening,
    Open,
    Closing,
  };

  class IChannel
  {
  private:
    UINT32 mChannelId;
    ChannelTypes mChannelType;
    TOnEventFunc mOnEvent;
    ChannelState mState;

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

    ChannelState State() const
    {
      return mState;
    }

    virtual TPacket CreateOpenPacket(PacketStore& store) = 0;
    virtual TPacket CreateClosePacket(PacketStore& store) = 0;
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
