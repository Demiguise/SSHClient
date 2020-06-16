#include "kex.h"
#include "dh_groups.h"
#include "constants.h"
#include "mpint.hpp"
#include "endian.h"

#include "wolfssl/wolfcrypt/dh.h"
#include "wolfssl/wolfcrypt/hash.h"

using namespace SSH;


class DH_KEXHandler : public SSH::IKEXHandler
{
  private:
    DhKey mPrivKey;
    WC_RNG mRNG;
    wc_HashAlg mHash;
    wc_HashType mHashType;

    struct
    {
      MPInt e;
      MPInt x;
    } mHandshake;

    bool mInitialised = false;

    bool HashBuffer(const Byte* pBuf, const UINT32 bufLen)
    {
      UINT32 tmpLen = swap_endian<uint32_t>(bufLen);
      int ret = wc_HashUpdate(&mHash, mHashType, (Byte*)&tmpLen, sizeof(UINT32));
      if (ret != 0)
      {
        return false;
      }

      ret = wc_HashUpdate(&mHash, mHashType, pBuf, bufLen);
      if (ret != 0)
      {
        return false;
      }

      return true;
    }

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
      wc_HashFree(&mHash, mHashType);
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

      //DH Key information now ready, setup hash
      switch (group)
      {
        case DHGroups::G_14:
          mHashType = WC_HASH_TYPE_SHA;
          break;
        default:
          mHashType = WC_HASH_TYPE_NONE;
          break;
      }

      ret = wc_HashInit(&mHash, mHashType);
      if (ret != 0)
      {
        return false;
      }

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

      UINT32 keyCertLen;
      std::vector<Byte> keyCerts;
      MPInt f;
      std::string signature;

      pDHReply->Read(keyCertLen);
      keyCerts.resize(keyCertLen);
      pDHReply->Read(keyCerts.data(), keyCertLen);

      pDHReply->Read(f);
      pDHReply->Read(signature);

      HashBuffer((Byte*)client.mIdent.c_str(), client.mIdent.length());
      HashBuffer((Byte*)server.mIdent.c_str(), server.mIdent.length());

      //Hash KEXInit packets
      HashBuffer(client.mKEXInit->Payload(), client.mKEXInit->PayloadLen());
      HashBuffer(server.mKEXInit->Payload(), server.mKEXInit->PayloadLen());

      //Hash server's HostKey

      //Hash MPInts e (client's) and f (server's)
      HashBuffer(mHandshake.e.mArr.data(), mHandshake.e.mLen);
      HashBuffer(f.mArr.data(), f.mLen);

      //Hash shared secret

      return false;
    }
};

TKEXHandler KEX::CreateDH(DHGroups group)
{
  std::shared_ptr<DH_KEXHandler> pHandler = std::make_shared<DH_KEXHandler>();

  pHandler->Init(group);

  return pHandler;
}
