#ifndef __PACKETS_H__
#define __PACKETS_H__

#include "ssh.h"

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
    Byte* mPacket;
    Byte* mIter;

    int mPacketLen;
    int mPayloadLen;
    Byte mPaddingLen;

  public:
    Packet(int packetSize);

    //Pointer to the beginning of the packet
    const Byte* const Data() const;
    int DataLen() const;

    //Pointer to the beginning of the payload
    const Byte* const Payload() const;
    int PayloadLen() const;

    int PaddingLen() const;

    bool Ready() const;

    bool InitFromBuffer(const Byte* pBuf, const int numBytes);
    int Consume(const Byte* pBuf, const int numBytes);

    //Will copy the data from the pBuf into the underlying packet buffer
    int Read(const Byte* pBuf, const int numBytes);

    int Write(const Byte data);
    int Write(const int data); //Will be treated as a UINT32 when writing
    int Write(const UINT32 data);
    int Write(const std::string data);
    int Write(const Byte* pBuf, const int numBytes);
  };

  namespace Packets
  {

    /*
      Returns a packet which is capable of fitting the given size.
      Users are responsible for returning the packets to this system through a ReturnPacket call.
      May allocate new resources for the packet.
      May return nullptr.
    */
    Packet* Get(size_t size);

    /*
      Returns a packet to the pool.
      Does not free the packet's resources.
    */
    void Return(Packet *oldPacket);

    /*
      Gets the 4 byte packet length from the beginning of SSH binary packet data.
    */
    UINT32 GetLength(const Byte* pBuf);

    /*
      Releases all packet un-used packet resources.
      If a client is currently using any packets, they must be returned BEFORE calling this
      to ensure the packet buffers are correctly freed.
    */
    void Cleanup();
  }
}

#endif //~__PACKETS_H__
