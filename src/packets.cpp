#include "packets.h"

#include "endian.h"

#include <array>
#include <map>
#include <vector>
#include <cmath>
#include <algorithm>

using namespace SSH;

/*
  Concrete template class for the packets
*/
template<std::size_t size>
class TPacket : public IPacket
{
private:
  constexpr static int payloadStart = sizeof(UINT32) + sizeof(Byte);

  using TArr = std::array<Byte, size>;
  TArr mPacket;

  //Iterator used for reading/writing
  typename TArr::iterator mIter;

  int mPacketLen;
  Byte mPaddingLen;
  int mPayloadLen;

public:
  TPacket(int packetSize)
    : mIter(mPacket.begin())
    , mPacketLen(packetSize)
    , mPaddingLen(0)
    , mPayloadLen(0)
  {}

  virtual const Byte* const Begin() const override
  {
    return mPacket.data();
  }

  virtual int Len() const override
  {
    return mPacketLen;
  }

  virtual const Byte* const Payload() const override
  {
    return &mPacket[payloadStart];
  }

  virtual int PayloadLen() const override
  {
    return mPayloadLen;
  }

  virtual int PaddingLen() const override
  {
    return mPaddingLen;
  }

  virtual bool Ready() const override
  {
    return mPacketLen == (mIter - mPacket.begin());
  }

  virtual bool Init(const Byte* pBuf, const int numBytes) override
  {
    if (numBytes < payloadStart)
    {
      //We need a minimum of 5 bytes for the packet and padding length
      return false;
    }

#ifdef _DEBUG
    //Sanity check the size of the packet
    if (GetPacketLength(pBuf) != mPacketLen)
    {
      return false;
    }

    //Sanity check we have enough space for the packet
    if (numBytes >= mPacketLen)
    {
      return false;
    }
#endif

    //Copy as much data into the packet buffer as possible
    int bytesToConsume = std::min(mPacketLen, numBytes);
    memcpy(&(*mIter), pBuf, bytesToConsume);
    mIter += bytesToConsume;

    //Extract padding length
    mPaddingLen = mPacket[sizeof(UINT32)];

    return true;
  }

  virtual int Consume(const Byte* pBuf, const int numBytes) override
  {
    //Get the number of bytes needed by this packet
    int bytesLeft = mPacketLen - (mIter - mPacket.begin());
    if (bytesLeft == 0)
    {
      return 0;
    }

    int bytesToConsume = std::min(bytesLeft, numBytes);
    memcpy(&(*mIter), pBuf, bytesToConsume);
    mIter += bytesToConsume;

    return bytesToConsume;
  }
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

IPacket* AllocatePacket(size_t requestedSize, size_t actualSize)
{
  IPacket* pNewPacket = nullptr;

#define MATCH_SIZE(numBytes) else if (requestedSize == numBytes) { pNewPacket = new TPacket<numBytes>(actualSize); }
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
    pNewPacket = AllocatePacket(requestedSize, size);
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
