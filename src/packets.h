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
  class Packet
  {
  private:
    using TPacketBytes = std::vector<Byte>;
    using TPacketIter = TPacketBytes::iterator;
    TPacketBytes mPacket;
    TPacketIter mIter = mPacket.begin();

    int mPacketLen = 0;
    int mPayloadLen = 0;
    Byte mPaddingLen = 0;

    Packet();

    static int GetLength(const Byte* pBuf);
  public:

    //Factory functions
    static std::shared_ptr<Packet> Create(int packetSize);
    static std::shared_ptr<Packet> Create(const Byte* pBuf, const int numBytes);

    //Pointer to the beginning of the payload
    const Byte* const Payload() const;
    int PayloadLen() const;

    bool Ready() const;

    //Will copy the data from the pBuf into the underlying packet buffer
    int Read(const Byte* pBuf, const int numBytes);

    int Write(const Byte data);
    int Write(const int data); //Will be treated as a UINT32 when writing
    int Write(const UINT32 data);
    int Write(const std::string data);
    int Write(const Byte* pBuf, const int numBytes);

    /*
      Prepares the packet for sending, writing any additional header
      information such as packet/padding length, MAC, and padding data.
    */
    void Prepare();
  };
}

#endif //~__PACKETS_H__
