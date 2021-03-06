#ifndef __MAC_H__
#define __MAC_H__

#include "ssh.h"
#include "name-list.h"
#include "crypto/key.hpp"

namespace SSH
{
  enum class MACHandlers
  {
    None,
    HMAC_SHA2_256
  };

  //Forward declare Packets here to remove the need to include the whole header
  class Packet;

  class IMACHandler
  {
  public:
    virtual ~IMACHandler() {}

    virtual bool SetKey(const Key& macKey) = 0;

    virtual UINT32 Len() = 0;
    virtual bool Create(const Packet* const pPacket, Byte* pOutMAC) = 0;
    virtual bool Verify(const Packet* const pPacket) = 0;

    virtual MACHandlers Type() = 0;
  };

  using TMACHandler = std::shared_ptr<IMACHandler>;

  namespace MAC
  {
    void PopulateNamelist(NameList& list);

    TMACHandler Create(MACHandlers handler);
    UINT32 Len(MACHandlers handler);
  }
}

#endif //~__MAC_H__

