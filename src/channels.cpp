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
  {}
};

TChannel Channels::Open(ChannelTypes type)
{
  return nullptr;
}
