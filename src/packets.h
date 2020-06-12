#ifndef __PACKETS_H__
#define __PACKETS_H__

#include "ssh.h"
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

  class Packet
  {
  protected:
    class Token {};

  private:
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

  public:
    enum class WriteMethod
    {
      WithLength,
      WithoutLength
    };

    using TSendFunc = std::function<int (const Byte*, const int)>;

    explicit Packet(Token);

    //Factory functions
    static TPacket Create(int payloadLen);

    //Returns a
    static std::pair<TPacket,int> Create(const Byte* pBuf, const int numBytes, const UINT32 seqNumber);

    //Pointer to the beginning of the payload
    const Byte* const Payload() const;
    int PayloadLen() const;

    //Number of bytes remaining to send/receive
    UINT32 Remaining() const;

    //Convinience function for checking if the packet is ready
    bool Ready() const { return Remaining() == 0; }

    UINT32 GetSequenceNumber() const { return mSequenceNumber; }

    //Will copy the data from the pBuf into the underlying packet buffer
    int Read(const Byte* pBuf, const int numBytes);

    int Write(const Byte data);
    int Write(const int data); //Will be treated as a UINT32 when writing
    int Write(const UINT32 data);
    int Write(const std::string data);
    int Write(const Byte* pBuf, const int numBytes, const WriteMethod method = WriteMethod::WithLength);

    /*
      Prepares the packet for sending, writing any additional header
      information such as packet/padding length, MAC, and padding data.
      Also resets the iterator to the beginning, preparing for sending.
    */
    void Prepare(const UINT32 seqNumber);

    int Send(TSendFunc sendFunc);
  };
}

#endif //~__PACKETS_H__
