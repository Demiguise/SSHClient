#include "kex.h"
#include "dh_groups.h"
#include "constants.h"
#include "mpint.hpp"

#include "wolfssl/wolfcrypt/dh.h"

using namespace SSH;


class DH_KEXHandler : public SSH::IKEXHandler
{
  private:
    DhKey mPrivKey;
    WC_RNG mRNG;

    struct
    {
      MPInt e;
      MPInt x;
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

      pPacket->Write((Byte)SSH_MSG::KEXDH_INIT);
      if (mHandshake.e.mPadding)
      {
        pPacket->Write((Byte)0);
      }
      pPacket->Write(mHandshake.e.mArr.data(), mHandshake.e.mLen);

      return pPacket;
    }

    bool VerifyReply(KEXData& server, KEXData& client, TPacket pDHReply) override
    {
      Byte msgId;

      //Verify this is a KEX packet
      pDHReply->Read(msgId);
      if (msgId != SSH_MSG::KEXDH_REPLY)
      {
        return false;
      }

      std::string keyCerts;
      MPInt f;
      std::string signature;

      pDHReply->Read(keyCerts);
      pDHReply->Read(f);
      pDHReply->Read(signature);

      //Get a buffer of the correct size to hold our pre-hash data
      int hashDataLen = client.mIdent.length() +
                        server.mIdent.length() +
                        client.mKEXInit->PayloadLen() +
                        server.mKEXInit->PayloadLen() +
                        0 + //HostKeyLen
                        mHandshake.e.mLen +
                        f.mLen +
                        0; //Shared secret

      auto hashData = std::vector<Byte>(hashDataLen);

      //Now fill the hashData with our values

      //Now hash the hashData

      //Validate the signature from the server

      return false;
    }
};

TKEXHandler KEX::CreateDH(DHGroups group)
{
  std::shared_ptr<DH_KEXHandler> pHandler = std::make_shared<DH_KEXHandler>();

  pHandler->Init(group);

  return pHandler;
}
