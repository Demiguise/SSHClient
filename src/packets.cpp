#include "packets.h"
#include "crypto/crypto.h"
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

const Byte* const Packet::Payload() const
{
  return &mPacket[payloadOffset];
}

int Packet::PayloadLen() const
{
  return mPayloadLen;
}

const Byte* const Packet::Begin() const
{
  return mPacket.data();
}

int Packet::PacketLen() const
{
  return mPacketLen;
}

const Byte* const Packet::MAC() const
{
  return &mPacket[mPacketLen + sizeof(UINT32)];
}

Byte* Packet::MAC_Unsafe()
{
  /*
    mPacketLen is Padding byte, payload, + padding.
    To find the MAC we must append the packet len field
  */
  return const_cast<Byte*>(MAC());
}

UINT32 Packet::Remaining() const
{
  return mTotalPacketLen - (mIter - mPacket.begin());
}

void Packet::Reset()
{
  mIter = mPacket.begin();
  std::fill(mIter, mPacket.end(), 0x00);
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

int Packet::Write(const SSH_MSG data)
{
  return Write((Byte)data);
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

int Packet::Write(const NameList data)
{
  return Write(data.Str());
}

int Packet::Write(const MPInt data)
{
  UINT32 len = data.Len();
  Write(len);

  std::memcpy(&(*mIter), data.Data(), len);
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

  outData.Init(&(*mIter), intLen);

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

int Packet::Read(TByteString& outData)
{
  UINT32 len = 0;
  Read(len);
  outData.resize(len);
  return Read(outData.data(), len) + sizeof(UINT32);
}

UINT32 Packet::GetLength(const Byte* pBuf)
{
  uint32_t nLen = *((uint32_t*)pBuf);
  return swap_endian<uint32_t>(nLen);
}

void Packet::PrepareWrite(const UINT32 seqNumber)
{
  if (mType != PacketType::Write)
  {
    //This should probably raise an error
    return;
  }

  if (mComplete)
  {
    //This should probably raise an error
    return;
  }

  //TODO: Write random bytes into the padding string
  std::fill(mIter, mIter+mPaddingLen, 0xAD);
  mSequenceNumber = seqNumber;
  mIter = mPacket.begin();

  //Write the MAC
  if (mMAC->Type() != MACHandlers::None)
  {
    mMAC->Create(this, MAC_Unsafe());
  }

  //Encrypt everything in the packet going out, apart from the MAC
  if (!mEncrypted && mCrypto->Encrypt(mPacket.data(), mPacketLen))
  {
    mEncrypted = true;
  }

  mComplete = true;
}

void Packet::PrepareRead()
{
  if (mType != PacketType::Read)
  {
    //This should probably raise an error
    return;
  }

  if (mComplete)
  {
    //This should probably raise an error
    return;
  }

  mIter = mPacket.begin() + payloadOffset;

  if (mEncrypted && mCrypto->Decrypt(mPacket.data(), mPacketLen))
  {
    mEncrypted = false;
  }

  mComplete = true;
}

int Packet::Send(TSendFunc sendFunc)
{
  auto bytesSent = sendFunc(&(*mIter), Remaining());
  mIter += bytesSent;
  return bytesSent;
}

PacketStore::PacketStore()
{
  //Ensure we have blank encryption/decryption ready
  mEncryptor = Crypto::Create(CryptoHandlers::None);
  mDecryptor = Crypto::Create(CryptoHandlers::None);

  mOutgoingMAC = MAC::Create(MACHandlers::None);
  mIncomingMAC = MAC::Create(MACHandlers::None);
}

std::shared_ptr<Packet> PacketStore::Create(int payloadLen, PacketType type)
{
  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  pPacket->mType = type;
  if (type == PacketType::Write)
  {
    pPacket->mMAC = mOutgoingMAC;
    pPacket->mCrypto = mEncryptor;
  }
  else
  {
    pPacket->mMAC = mIncomingMAC;
    pPacket->mCrypto = mDecryptor;

    //We're assuming that if a cryptographic handler has been set, incoming packets are encrypted.
    if (pPacket->mCrypto->Type() != CryptoHandlers::None)
    {
      pPacket->mEncrypted = true;
    }
  }

  /*
    Figure out how much padding we need.
  */
  UINT32 macLen = pPacket->mMAC->Len();
  pPacket->mTotalPacketLen =  sizeof(UINT32) +  //packet_length
                              sizeof(Byte) +    //padding_length
                              payloadLen +      //payload
                              macLen;           //MAC

  /*
    Now figure out how much padding we need.
  */
  UINT32 blockLen = std::max(8u, pPacket->mCrypto->BlockLen());
  UINT32 padding = (blockLen - (pPacket->mTotalPacketLen % blockLen));
  if (padding < minPaddingSize)
  {
    //Simple way to ensure we have our minimum
    padding += blockLen;
  }

  pPacket->mTotalPacketLen += padding;
  pPacket->mPaddingLen = padding;
  pPacket->mPayloadLen = payloadLen;

  //PacketLen is payload + padding + 1 byte for the padding_length field
  pPacket->mPacketLen = payloadLen + pPacket->mPaddingLen + sizeof(Byte);
  pPacket->mPacket.reserve(pPacket->mTotalPacketLen);
  pPacket->mPacket.resize(pPacket->mTotalPacketLen);

#ifdef _DEBUG
  //Helps to identify exactly which bytes have been allocated for the packet
  std::fill(pPacket->mPacket.begin(), pPacket->mPacket.end(), 0xDE);
#endif

  pPacket->mIter = pPacket->mPacket.begin();

  //We can immediately write the packet and padding length here
  pPacket->Write(pPacket->mPacketLen);
  pPacket->Write((Byte)pPacket->mPaddingLen);

  return pPacket;
}

std::pair<TPacket, int> PacketStore::Create(const Byte* pBuf, const int numBytes, const UINT32 seqNumber, PacketType type)
{
  if (numBytes < payloadOffset)
  {
    //We need a minimum of 5 bytes for the packet and padding length
    return {nullptr, 0};
  }

  auto pPacket = std::make_shared<Packet>(typename Packet::Token{});

  pPacket->mType = type;
  if (type == PacketType::Write)
  {
    pPacket->mMAC = mOutgoingMAC;
    pPacket->mCrypto = mEncryptor;
  }
  else
  {
    pPacket->mMAC = mIncomingMAC;
    pPacket->mCrypto = mDecryptor;

    //We're assuming that if a cryptographic handler has been set, incoming packets are encrypted.
    if (pPacket->mCrypto->Type() != CryptoHandlers::None)
    {
      pPacket->mEncrypted = true;
    }
  }

  /*
    packetLen does NOT include the MAC or the packetLen field itself.
    When copying the buffer data into our packet, we will want to take this into account
    via the fullPacketLen field.
  */
  const Byte* pIter = pBuf;
  UINT32 packetLen = Packet::GetLength(pIter);
  pPacket->mTotalPacketLen = packetLen + sizeof(UINT32);
  pPacket->mPacketLen = packetLen;
  pPacket->mPacket.reserve(pPacket->mTotalPacketLen);
  pPacket->mPacket.resize(pPacket->mTotalPacketLen);

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

TPacket PacketStore::Copy(TPacket pPacket)
{
  TPacket pNewPacket = Create(pPacket->mPayloadLen, pPacket->mType);
  std::copy(pPacket->mPacket.begin(), pPacket->mPacket.end(), pNewPacket->mPacket.begin());
  pNewPacket->mIter = pNewPacket->mPacket.begin() + (pPacket->mIter - pPacket->mPacket.begin());
  pNewPacket->mSequenceNumber = pPacket->mSequenceNumber;

  pNewPacket->mCrypto = pPacket->mCrypto;
  pNewPacket->mMAC = pPacket->mMAC;
  pNewPacket->mType = pPacket->mType;

  return pNewPacket;
}

void PacketStore::SetEncryptionHandler(TCryptoHandler handler)
{
  mEncryptor = handler;
}

void PacketStore::SetDecryptionHandler(TCryptoHandler handler)
{
  mDecryptor = handler;
}

void PacketStore::SetOutgoingMACHandler(TMACHandler handler)
{
  mOutgoingMAC = handler;
}

void PacketStore::SetIncomingMACHandler(TMACHandler handler)
{
  mIncomingMAC = handler;
}
