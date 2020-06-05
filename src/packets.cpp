#include "packets.h"

#include "endian.h"

#include <array>
#include <map>
#include <vector>
#include <cmath>

using namespace SSH;

/*
  Concrete template class for the packets
*/
template<std::size_t size>
class TPacket : public IPacket
{
private:
  using TArr = std::array<Byte, size>;
  TArr mPayload;
  typename TArr::iterator mIter;

public:
  TPacket()
    : mIter(mPayload.begin())
  {}

  virtual const Byte* const Payload() const override
  {
    return mPayload.data();
  }

  virtual int PayloadLen() const override
  {
    return 0;
  }

  virtual void Consume(const Byte* pBuf, const int numBytes) override
  {}
};

using TPacketVec = std::vector<IPacket*>;
using TPacketMap = std::map<int, TPacketVec>;

#define INIT_SIZE(size) { size, {} }
static TPacketMap gPacketMap = {
  INIT_SIZE(16),
  INIT_SIZE(32),
  INIT_SIZE(64),
  INIT_SIZE(128),
  INIT_SIZE(256),
  INIT_SIZE(512),
  INIT_SIZE(1024),
  INIT_SIZE(2048),
  INIT_SIZE(4096),
  INIT_SIZE(8192),
  INIT_SIZE(16384),
  INIT_SIZE(32768),
};
#undef INIT_SIZE

/*
  Round up a packet size to the nearest multiple of 2.
  Return value of 0 indicates the packet request is too big
*/
size_t RoundUp(size_t size)
{
#define MATCH_SIZE(numBytes) if (size <= numBytes) { return numBytes; }
  MATCH_SIZE(16)
  MATCH_SIZE(32)
  MATCH_SIZE(64)
  MATCH_SIZE(128)
  MATCH_SIZE(256)
  MATCH_SIZE(512)
  MATCH_SIZE(1024)
  MATCH_SIZE(2048)
  MATCH_SIZE(4096)
  MATCH_SIZE(8192)
  MATCH_SIZE(16384)
  MATCH_SIZE(32768)

  //If it's bigger than 32kib then we fail to find a packet
  return 0;
#undef MATCH_SIZE
}

IPacket* AllocatePacket(size_t requestedSize)
{
  IPacket* pNewPacket = nullptr;

#define MATCH_SIZE(numBytes) else if (requestedSize == numBytes) { pNewPacket = new TPacket<numBytes>(); }
  if (false) {} //God I hate this
  MATCH_SIZE(16)
  MATCH_SIZE(32)
  MATCH_SIZE(64)
  MATCH_SIZE(128)
  MATCH_SIZE(256)
  MATCH_SIZE(512)
  MATCH_SIZE(1024)
  MATCH_SIZE(2048)
  MATCH_SIZE(4096)
  MATCH_SIZE(8192)
  MATCH_SIZE(16384)
  MATCH_SIZE(32768)

  //If it's bigger than 32kib then we fail to find a packet
  return pNewPacket;
#undef MATCH_SIZE
}

IPacket* SSH::GetPacket(size_t size)
{
  size_t requestedSize = RoundUp(size);
  if (requestedSize == 0)
  {
    return nullptr;
  }

  TPacketVec& freePackets = gPacketMap[requestedSize];
  IPacket* pNewPacket = nullptr;

  if (freePackets.empty())
  {
    pNewPacket = AllocatePacket(requestedSize);
  }
  else
  {
    pNewPacket = freePackets.back();
    freePackets.pop_back();
  }

  return pNewPacket;
}

UINT32 SSH::GetPacketLength(const Byte* pBuf)
{
  uint32_t nLen = *((uint32_t*)pBuf);
  return swap_endian<uint32_t>(nLen);
}
