#ifndef __KEX_H__
#define __KEX_H__

#include <memory>
#include "ssh.h"
#include "packets.h"

namespace SSH
{
  //For now, we're only going to do Diffie Helman
  enum class DHGroups
  {
    G_14,
  };

  class IKEXHandler
  {
    public:
      IKEXHandler() = default;
      virtual ~IKEXHandler() = default;

      virtual TPacket CreateInitPacket() = 0;
  };

  using TKEXHandler = std::shared_ptr<IKEXHandler>;
  namespace KEX
  {
    TKEXHandler CreateDH(DHGroups group);
  }
}

#endif //~__KEX_H__
