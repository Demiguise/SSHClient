#include "packets.h"

#include "endian.h"

#include <array>
#include <map>
#include <vector>
#include <cmath>
#include <algorithm>

using namespace SSH;

constexpr static int payloadStart = sizeof(UINT32) + sizeof(Byte);

Packet::Packet(int packetSize)
  : mIter(mPacket)
  , mPacketLen(packetSize)
  , mPaddingLen(0)
  , mPayloadLen(0)
{}

const Byte* const Packet::Data() const
{
  return mPacket;
}

int Packet::DataLen() const
{
  return mPacketLen;
}

const Byte* const Packet::Payload() const
{
  return &mPacket[payloadStart];
}

int Packet::PayloadLen() const
{
  return mPayloadLen;
}

int Packet::PaddingLen() const
{
  return mPaddingLen;
}

bool Packet::Ready() const
{
  return mPayloadLen == (mIter - mPacket);
}

bool Packet::InitFromBuffer(const Byte* pBuf, const int numBytes)
{
  if (numBytes < payloadStart)
  {
    //We need a minimum of 5 bytes for the packet and padding length
    return false;
  }

#ifdef _DEBUG
  //Sanity check the size of the packet
  if (Packets::GetLength(pBuf) != mPacketLen)
  {
    return false;
  }

  //Sanity check we have enough space for the packet
  if (numBytes >= mPacketLen)
  {
    return false;
  }
#endif

  int bytesRemaining = numBytes;
  const Byte* pIter = pBuf;

  //Packet Length (Just skip past)
  pIter += sizeof(UINT32);
  bytesRemaining -= sizeof(UINT32);

  //Padding length
  mPaddingLen = *(pIter);
  pIter += sizeof(Byte);
  bytesRemaining -= sizeof(Byte);

  mPayloadLen = mPacketLen - mPaddingLen - 1;

  int bytesToConsume = std::min(mPayloadLen, bytesRemaining);
  memcpy(mIter, pIter, bytesToConsume);
  mIter += bytesToConsume;

  return true;
}

int Packet::Consume(const Byte* pBuf, const int numBytes)
{
  //Get the number of bytes needed by this packet
  int bytesLeft = mPayloadLen - (mIter - mPacket);
  if (bytesLeft == 0)
  {
    return 0;
  }

  int bytesToConsume = std::min(bytesLeft, numBytes);
  memcpy(mIter, pBuf, bytesToConsume);
  mIter += bytesToConsume;

  return bytesToConsume;
}

int Packet::Write(const Byte data)
{
  *mIter = data;
  mIter += sizeof(Byte);
  return sizeof(Byte);
}

int Packet::Write(const int data)
{
  return Write((UINT32)data);
}

int Packet::Write(const UINT32 data)
{
  UINT32* pIter = (UINT32*)mIter;
  *pIter = swap_endian<uint32_t>(data);
  mIter += sizeof(UINT32);
  return sizeof(UINT32);
}

int Packet::Write(const std::string data)
{
  UINT32 len = data.length();
  Write(len);
  memcpy(mIter, data.data(), len);
  mIter += len;
  return len + sizeof(UINT32);
}

int Packet::Write(const Byte* pBuf, const int numBytes)
{
  Write(numBytes);
  memcpy(mIter, pBuf, numBytes);
  mIter += numBytes;
  return numBytes + sizeof(UINT32);
}

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
