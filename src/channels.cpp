#include "channels.h"

using namespace SSH;

class Channel : public IChannel
{
private:
  UINT32 mChannelId;
  ChannelTypes mChannelType;

public:
  Channel(ChannelTypes type, UINT32 id)
    : mChannelId(id)
    , mChannelType(type)
  {
  }

  virtual ~Channel()
  {
  }

  virtual UINT32 ID() const override { return mChannelId; }
  virtual ChannelTypes Type() const override { return mChannelType; }
};

TChannel ChannelManager::Open(ChannelTypes type)
{
  return std::make_shared<Channel>(type, mNextID++);
}
