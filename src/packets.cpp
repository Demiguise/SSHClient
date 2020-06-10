#include "packets.h"

#include "endian.h"

#include <array>
#include <map>
#include <vector>
#include <cmath>
#include <algorithm>

using namespace SSH;

constexpr static int payloadOffset = sizeof(UINT32) + sizeof(Byte);

std::shared_ptr<Packet> Packet::Create(int packetSize)
{
  auto pPacket = std::make_shared<Packet>();

  pPacket->mPacketLen = packetSize;
  pPacket->mPacket.reserve(packetSize);

  return pPacket;
}

std::shared_ptr<Packet> Packet::Create(const Byte* pBuf, const int numBytes)
{
  if (numBytes < payloadOffset)
  {
    //We need a minimum of 5 bytes for the packet and padding length
    return nullptr;
  }

  auto pPacket = std::make_shared<Packet>();

  const Byte* pIter = pBuf;
  UINT32 packetLen = GetLength(pIter);
  pPacket->mPacketLen = packetLen;
  pPacket->mPacket.reserve(packetLen);

  pIter += sizeof(UINT32);
  UINT32 paddingLen = *(pIter);
  pPacket->mPaddingLen = paddingLen;
  pPacket->mPayloadLen = (packetLen - paddingLen - 1);

  UINT32 bytesToConsume = std::min(packetLen, (UINT32)numBytes);
  memcpy(pBuf, pPacket->mPacket.data(), bytesToConsume);

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

bool Packet::Ready() const
{
  return mPayloadLen == (mIter - mPacket.begin());
}

int Packet::Read(const Byte* pBuf, const int numBytes)
{
  //Get the number of bytes needed by this packet
  int bytesLeft = mPayloadLen - (mIter - mPacket.begin());
  if (bytesLeft == 0)
  {
    return 0;
  }

  int bytesToConsume = std::min(bytesLeft, numBytes);
  memcpy(&(*mIter), pBuf, bytesToConsume);
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
  memcpy(&(*mIter), data.data(), len);
  mIter += len;
  return len + sizeof(UINT32);
}

int Packet::Write(const Byte* pBuf, const int numBytes)
{
  Write(numBytes);
  memcpy(&(*mIter), pBuf, numBytes);
  mIter += numBytes;
  return numBytes + sizeof(UINT32);
}


UINT32 Packet::GetPacketLength(const Byte* pBuf)
{
  uint32_t nLen = *((uint32_t*)pBuf);
  return swap_endian<uint32_t>(nLen);
}
