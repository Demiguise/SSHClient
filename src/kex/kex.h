#ifndef __KEX_H__
#define __KEX_H__

#include <memory>
#include "ssh.h"
#include "name-list.h"
#include "packets.h"

namespace SSH
{
  struct ListPairs
  {
    NameList mClientToServer;
    NameList mServerToClient;
  };

  struct KEXData
  {
    struct
    {
      NameList mKex;
      NameList mServerHost;
      ListPairs mEncryption;
      ListPairs mMAC;
      ListPairs mCompression;
      ListPairs mLanguages;
    } mAlgorithms;

    std::string mServerIdent;
    TPacket mKEXInit;
  };

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
      virtual bool VerifyReply(KEXData& server, KEXData& client, TPacket pDHReply) = 0;
  };

  using TKEXHandler = std::shared_ptr<IKEXHandler>;
  namespace KEX
  {
    TKEXHandler CreateDH(DHGroups group);
  }
}

#endif //~__KEX_H__
