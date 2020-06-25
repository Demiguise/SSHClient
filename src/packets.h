#ifndef __PACKETS_H__
#define __PACKETS_H__

#include "ssh.h"
#include "name-list.h"
#include "mpint.h"
#include "constants.h"
#include "crypto/crypto.h"
#include "mac.h"
#include <vector>

namespace SSH
{
  /*
    Packet manages a buffer for reads/writes and should be used
    for the binary message protocol.
    Packets are sized so that the payload is always a multiple of 16 bytes, with
    enough extra space for header and MAC information.
  */
  class Packet;
  using TPacket = std::shared_ptr<Packet>;

  using TByteString = std::vector<Byte>;

  enum class PacketType
  {
    Read,
    Write
  };

  class Packet
  {
  protected:
    class Token {};

  private:
    friend class PacketStore;

    using TPacketBytes = std::vector<Byte>;
    using TPacketIter = TPacketBytes::iterator;
    TPacketBytes mPacket;
    TPacketIter mIter = mPacket.begin();

    int mPacketLen = 0; //Value of the packet_length field
    int mTotalPacketLen = 0; //Size of the whole packet include packet_length and MAC
    int mPayloadLen = 0; //Calculated value based on packet_length and padding_length
    Byte mPaddingLen = 0; //Value of the padding_length field

    UINT32 mSequenceNumber = 0;

    static UINT32 GetLength(const Byte* pBuf);

    //Set by the packet store on creation
    TCryptoHandler mCrypto;
    TMACHandler mMAC;

    PacketType mType;
    bool mEncrypted = false;

    Byte* Payload_Unsafe();

  public:
    enum class WriteMethod
    {
      WithLength,
      WithoutLength
    };

    using TSendFunc = std::function<int (const Byte*, const int)>;

    explicit Packet(Token);

    //Pointer to the beginning of the payload
    const Byte* const Payload() const;
    int PayloadLen() const;

    //Number of bytes remaining to send/receive
    UINT32 Remaining() const;

    //Convinience function for checking if the packet is ready
    bool Ready() const { return Remaining() == 0; }

    //Clears the packet's payload and resets the iterator back to the beginning
    void Reset();

    UINT32 GetSequenceNumber() const { return mSequenceNumber; }

    //Will copy the data from the pBuf into the underlying packet buffer
    int Consume(const Byte* pBuf, const int numBytes);

    int Write(const Byte data);
    int Write(const SSH_MSG data);
    int Write(const int data); //Will be treated as a UINT32 when writing
    int Write(const UINT32 data);
    int Write(const std::string data);
    int Write(const NameList outData);
    int Write(const MPInt data);
    int Write(const Byte* pBuf, const int numBytes, const WriteMethod method = WriteMethod::WithLength);

    int Read(Byte& outData);
    int Read(UINT32& data);
    int Read(std::string& outData);
    int Read(NameList& outData);
    int Read(MPInt& outData);
    int Read(Byte* pOutBuf, int outBufLen);
    int Read(TByteString& outData);

    /*
      Prepares the packet for sending, writing any additional header
      information such as packet/padding length, MAC, and padding data.
      Also resets the iterator to the beginning, preparing for sending.
    */
    void PrepareWrite(const UINT32 seqNumber);

    /*
      Prepares the packet for reading, setting the iterator to the beginning
      of the payload.
    */
    void PrepareRead();

    int Send(TSendFunc sendFunc);
  };

  /*
    Handles all aspects of creating, copying, freeing packets for a given SSH connection.
    In addition, users must set the encryption/mac handlers on the packetstore so packets may
    be correctly encrypted after the newkeys message.
  */
  class PacketStore
  {
  private:
    TCryptoHandler mEncryptor;
    TCryptoHandler mDecryptor;

    TMACHandler mOutgoingMAC;
    TMACHandler mIncomingMAC;

  public:
    PacketStore();

    TPacket Create(int payloadLen, PacketType type);
    std::pair<TPacket,int> Create(const Byte* pBuf, const int numBytes, const UINT32 seqNumber, PacketType type);
    TPacket Copy(TPacket pPacket);

    //Crypto handlers are expected to be fully setup by the time they are passed here
    void SetEncryptionHandler(TCryptoHandler handler);
    void SetDecryptionHandler(TCryptoHandler handler);

    //MAC handlers are expected to be fully setup by the time they are passed here
    void SetOutgoingMACHandler(TMACHandler handler);
    void SetIncomingMACHandler(TMACHandler handler);
  };
}

#endif //~__PACKETS_H__
