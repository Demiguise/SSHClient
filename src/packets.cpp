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
constexpr static int minPaddingSize = 4; //RFC states there should be a minimum of 4 bytes

Packet::Packet(Token t) {}

std::shared_ptr<Packet> Packet::Create(int payloadLen)
{
  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  /*
    Figure out how much padding we need.
    TODO: Take into account the MAC length here
  */
  pPacket->mTotalPacketLen =  sizeof(UINT32) +  //packet_length
                              sizeof(Byte) +    //padding_length
                              payloadLen;       //payload

  /*
    Now figure out how much padding we need.
    Forcing multiple of 8 until we have block ciphers.
  */
  UINT32 padding = (8 - (pPacket->mTotalPacketLen % 8));
  if (padding < minPaddingSize)
  {
    //Simple way to ensure we have our minimum
    padding += 8;
  }

  pPacket->mTotalPacketLen += padding;
  pPacket->mPaddingLen = padding;

  //PacketLen is payload + padding + 1 byte for the padding_length field
  pPacket->mPacketLen = payloadLen + pPacket->mPaddingLen + sizeof(Byte);
  pPacket->mPacket.reserve(pPacket->mTotalPacketLen);
  pPacket->mPacket.resize(pPacket->mTotalPacketLen);

  pPacket->mIter = pPacket->mPacket.begin();

  //We can immediately write the packet and padding length here
  pPacket->Write(pPacket->mPacketLen);
  pPacket->Write((Byte)pPacket->mPaddingLen);

  return pPacket;
}

std::pair<TPacket, int> Packet::Create(const Byte* pBuf, const int numBytes, const UINT32 seqNumber)
{
  if (numBytes < payloadOffset)
  {
    //We need a minimum of 5 bytes for the packet and padding length
    return {nullptr, 0};
  }

  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  /*
    packetLen does NOT include the MAC or the packetLen field itself.
    When copying the buffer data into our packet, we will want to take this into account
    via the fullPacketLen field.
  */
  const Byte* pIter = pBuf;
  UINT32 packetLen = GetLength(pIter);
  pPacket->mTotalPacketLen = packetLen + sizeof(UINT32);
  pPacket->mPacketLen = packetLen;
  pPacket->mPacket.reserve(packetLen + pPacket->mTotalPacketLen);
  pPacket->mPacket.resize(packetLen + pPacket->mTotalPacketLen);

  pIter += sizeof(UINT32);
  UINT32 paddingLen = *(pIter);
  pPacket->mPaddingLen = paddingLen;
  pPacket->mPayloadLen = (packetLen - paddingLen - sizeof(Byte));

  UINT32 bytesToConsume = std::min(pPacket->mTotalPacketLen, numBytes);
  std::memcpy(pPacket->mPacket.data(), pBuf, bytesToConsume);

  pPacket->mIter = (pPacket->mPacket.begin() + bytesToConsume);

  pPacket->mSequenceNumber = seqNumber;

  return {pPacket, bytesToConsume};
}

TPacket Packet::Copy(TPacket pPacket)
{
  TPacket pNewPacket = Create(pPacket->mPayloadLen);
  std::copy(pPacket->mPacket.begin(), pPacket->mPacket.end(), pNewPacket->mPacket.begin());
  return pNewPacket;
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
  return mTotalPacketLen - (mIter - mPacket.begin());
}

int Packet::Consume(const Byte* pBuf, const int numBytes)
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

int Packet::Write(const Byte* pBuf, const int numBytes, const WriteMethod method /*=::WithLength*/)
{
  if (method == WriteMethod::WithLength)
  {
    Write(numBytes);
  }

  std::memcpy(&(*mIter), pBuf, numBytes);
  mIter += numBytes;
  return numBytes + sizeof(UINT32);
}

int Packet::Read(Byte& outData)
{
  outData = *mIter;
  mIter += sizeof(Byte);
  return sizeof(Byte);
}

int Packet::Read(UINT32& outData)
{
  UINT32* pIter = (UINT32*)&(*mIter);
  outData = swap_endian<uint32_t>(*pIter);

  mIter += sizeof(UINT32);
  return sizeof(UINT32);
}

int Packet::Read(std::string& outData)
{
  UINT32 stringLen = 0;
  Read(stringLen);

  outData.assign((char*)&(*mIter), stringLen);
  mIter += stringLen;
  return stringLen + sizeof(UINT32);
}

int Packet::Read(NameList& outData)
{
  UINT32 namelistLen = 0;
  Read(namelistLen);

  outData.Init(&(*mIter), namelistLen);
  mIter += namelistLen;
  return namelistLen + sizeof(UINT32);
}

int Packet::Read(MPInt& outData)
{
  UINT32 intLen = 0;
  Read(intLen);

  std::copy(mIter, mIter + intLen, outData.mArr.begin());
  outData.mLen = intLen;
  mIter += intLen;
  return intLen + sizeof(UINT32);
}

int Packet::Read(Byte* pOutBuf, int bytesToRead)
{
  if (Remaining() < bytesToRead)
  {
    return -1;
  }

  memcpy(pOutBuf, &(*mIter), bytesToRead);
  mIter += bytesToRead;
  return bytesToRead;
}

UINT32 Packet::GetLength(const Byte* pBuf)
{
  uint32_t nLen = *((uint32_t*)pBuf);
  return swap_endian<uint32_t>(nLen);
}

void Packet::PrepareWrite(const UINT32 seqNumber)
{
  //TODO: Write random bytes into the padding string
  memset(&(*mIter), 0xAD, mPaddingLen);
  mSequenceNumber = seqNumber;
  mIter = mPacket.begin();
}

void Packet::PrepareRead()
{
  mIter = mPacket.begin() + payloadOffset;
}

int Packet::Send(TSendFunc sendFunc)
{
  auto bytesSent = sendFunc(&(*mIter), Remaining());
  mIter += bytesSent;
  return bytesSent;
}
