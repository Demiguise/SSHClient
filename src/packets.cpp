#include "packets.h"

#include "endian.h"

#include <array>
#include <map>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>

using namespace SSH;

constexpr static int payloadOffset = sizeof(UINT32) + sizeof(Byte);

Packet::Packet(Token t) {}

std::shared_ptr<Packet> Packet::Create(int packetSize)
{
  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  pPacket->mPacketLen = packetSize;
  pPacket->mPacket.reserve(packetSize);
  pPacket->mPacket.resize(packetSize);
  pPacket->mIter = pPacket->mPacket.begin();

  return pPacket;
}

std::shared_ptr<Packet> Packet::Create(const Byte* pBuf, const int numBytes)
{
  if (numBytes < payloadOffset)
  {
    //We need a minimum of 5 bytes for the packet and padding length
    return nullptr;
  }

  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  const Byte* pIter = pBuf;
  UINT32 packetLen = GetLength(pIter);
  pPacket->mPacketLen = packetLen;
  pPacket->mPacket.reserve(packetLen);
  pPacket->mPacket.resize(packetLen);


  pIter += sizeof(UINT32);
  UINT32 paddingLen = *(pIter);
  pPacket->mPaddingLen = paddingLen;
  pPacket->mPayloadLen = (packetLen - paddingLen - 1);

  UINT32 bytesToConsume = std::min(packetLen, (UINT32)numBytes);
  std::memcpy(pPacket->mPacket.data(), pBuf, bytesToConsume);

  pPacket->mIter = (pPacket->mPacket.begin() + bytesToConsume);

  return pPacket;
}

const Byte* const Packet::Payload() const
{
  return &mPacket[payloadOffset];
}

int Packet::PayloadLen() const
{
  return mPayloadLen;
}

UINT32 Packet::Remaining() const
{
  return mPacketLen - (mIter - mPacket.begin());
}

int Packet::Read(const Byte* pBuf, const int numBytes)
{
  //Get the number of bytes needed by this packet
  int bytesLeft = Remaining();
  if (bytesLeft == 0)
  {
    return 0;
  }

  int bytesToConsume = std::min(bytesLeft, numBytes);
  std::memcpy(&(*mIter), pBuf, bytesToConsume);
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
  UINT32* pIter = (UINT32*)&(*mIter);
  *pIter = swap_endian<uint32_t>(data);
  mIter += sizeof(UINT32);
  return sizeof(UINT32);
}

int Packet::Write(const std::string data)
{
  UINT32 len = data.length();
  Write(len);
  std::memcpy(&(*mIter), data.data(), len);
  mIter += len;
  return len + sizeof(UINT32);
}

int Packet::Write(const Byte* pBuf, const int numBytes)
{
  Write(numBytes);
  std::memcpy(&(*mIter), pBuf, numBytes);
  mIter += numBytes;
  return numBytes + sizeof(UINT32);
}

UINT32 Packet::GetLength(const Byte* pBuf)
{
  uint32_t nLen = *((uint32_t*)pBuf);
  return swap_endian<uint32_t>(nLen);
}
