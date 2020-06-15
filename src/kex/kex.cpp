#include "kex.h"
#include "dh_groups.h"
#include "constants.h"
#include "mpint.hpp"

#include "wolfssl/wolfcrypt/dh.h"

using namespace SSH;

#define MAX_KEX_KEY_SZ (8192 / 8)

class DH_KEXHandler : public SSH::IKEXHandler
{
  private:
    DhKey mPrivKey;
    WC_RNG mRNG;

    struct
    {
      MPInt<MAX_KEX_KEY_SZ+1> e;
      MPInt<MAX_KEX_KEY_SZ+1> x;
    } mHandshake;

    bool mInitialised = false;

  public:
    DH_KEXHandler()
    {}

    ~DH_KEXHandler()
    {
      if (!mInitialised)
      {
        return;
      }

      wc_FreeDhKey(&mPrivKey);
    }

    bool Init(DHGroups group)
    {
      int ret = wc_InitDhKey(&mPrivKey);
      if (ret != 0)
      {
        return false;
      }

      ret = wc_InitRng(&mRNG);
      if (ret != 0)
      {
        return false;
      }

      ret = wc_DhSetKey(&mPrivKey,
                        sDHGroup14.data.data(), sDHGroup14.data.size(),
                        &sDHGroup14.generator, sizeof(Byte));
      if (ret != 0)
      {
        return false;
      }

      ret = wc_DhGenerateKeyPair(&mPrivKey, &mRNG,
                                 mHandshake.x.mArr.data(), &mHandshake.x.mLen,
                                 mHandshake.e.mArr.data(), &mHandshake.e.mLen);
      if (ret != 0)
      {
        return false;
      }

      //DH Key information now ready

      return true;
    }

    TPacket CreateInitPacket() override
    {
      mHandshake.e.Prepare();

      //Calculate the length of the packet
      int packetLen = sizeof(Byte) + //MSG_ID
                      sizeof(UINT32) + //Length
                      mHandshake.e.mLen +
                      ((mHandshake.e.mPadding) ? 1 : 0);

      auto pPacket = Packet::Create(packetLen);

      pPacket->Write(SSH_MSG::KEXDH_INIT);
      if (mHandshake.e.mPadding)
      {
        pPacket->Write((Byte)0);
      }
      pPacket->Write(mHandshake.e.mArr.data(), mHandshake.e.mLen);

      return pPacket;
    }
};

TKEXHandler KEX::CreateDH(DHGroups group)
{
  std::shared_ptr<DH_KEXHandler> pHandler = std::make_shared<DH_KEXHandler>();

  pHandler->Init(group);

  return pHandler;
}
