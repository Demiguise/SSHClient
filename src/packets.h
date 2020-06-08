#ifndef __PACKETS_H__
#define __PACKETS_H__

#include "ssh.h"

namespace SSH
{
  /*
    Interface class to hide away the size of the underlying packets,
    and provide a consistent interface for users.
  */
  class IPacket
  {
  public:
    virtual const Byte* const Begin() const = 0;
    virtual int Len() const = 0;

    virtual const Byte* const Payload() const = 0;
    virtual int PayloadLen() const = 0;

    virtual int PaddingLen() const = 0;

    virtual bool Init(const Byte* pBuf, const int numBytes) = 0;
    virtual int Consume(const Byte* pBuf, const int numBytes) = 0;
  };

  /*
    Returns a packet which is capable of fitting the given size.
    Users are responsible for returning the packets to this system through a ReturnPacket call.
    May allocate new resources for the packet.
    May return nullptr.
  */
  IPacket* GetPacket(size_t size);

  /*
    Returns a packet to the pool.
    Does not free the packet's resources.
  */
  void ReturnPacket(IPacket* oldPacket);

  /*
    Gets the 4 byte packet length from the beginning of SSH binary packet data.
  */
  UINT32 GetPacketLength(const Byte* pBuf);
}

#endif //~__PACKETS_H__
