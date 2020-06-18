#include "kex.h"
#include "dh_groups.h"
#include "constants.h"
#include "mpint.h"
#include "endian.h"

//Temporarily include this win10 user settings, otherwise we encounter stack smashing
#include <IDE/WIN10/user_settings.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>

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
                      mHandshake.e.mLen;

      auto pPacket = Packet::Create(packetLen);

      pPacket->Write((Byte)SSH_MSG::KEXDH_INIT);
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
      UINT32 signatureLen;
      std::vector<Byte> signature;

      pDHReply->Read(keyCertLen);
      keyCerts.resize(keyCertLen);
      pDHReply->Read(keyCerts.data(), keyCertLen);

      pDHReply->Read(f);

      pDHReply->Read(signatureLen);
      signature.resize(signatureLen);
      pDHReply->Read(signature.data(), signatureLen);

      //Hash identifiers
      HashBuffer((Byte*)client.mIdent.c_str(), client.mIdent.length());
      HashBuffer((Byte*)server.mIdent.c_str(), server.mIdent.length());

      //Hash KEXInit packets
      HashBuffer(client.mKEXInit->Payload(), client.mKEXInit->PayloadLen());
      HashBuffer(server.mKEXInit->Payload(), server.mKEXInit->PayloadLen());

      //Hash server's HostKey data (The entire buffer)
      HashBuffer(keyCerts.data(), keyCertLen);

      //Hash MPInts e (client's) and f (server's)
      HashBuffer(mHandshake.e.mArr.data(), mHandshake.e.mLen);
      HashBuffer(f.mArr.data(), f.mLen);

      //Decode server's host key
      RsaKey key;
      {
        int ret = wc_InitRsaKey(&key, NULL);
        if (ret != 0)
        {
          return false;
        }

        auto iter = keyCerts.begin();

        UINT32 hostKeyTypeLen = 0;
        hostKeyTypeLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        std::string hostKeyType;
        hostKeyType.assign((char*)&(*iter), hostKeyTypeLen);
        iter += hostKeyTypeLen;

        MPInt e;
        MPInt n;

        UINT32 eLen = 0;
        eLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        std::copy(iter, iter+eLen, e.mArr.begin());
        iter += eLen;

        UINT32 nLen = 0;
        nLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        std::copy(iter, iter+eLen, n.mArr.begin());
        iter += nLen;

        ret = wc_RsaPublicKeyDecodeRaw(n.mArr.data(), n.mLen, e.mArr.data(), e.mLen, &key);
        if (ret != 0)
        {
          return false;
        }
      }
      //Generate shared secret
      MPInt k;
      int ret = wc_DhAgree( &mPrivKey, k.mArr.data(), &k.mLen,
                            mHandshake.x.mArr.data(), mHandshake.x.mLen,
                            f.mArr.data(), f.mLen);
      if (ret != 0)
      {
        return false;
      }

      //Hash shared secret
      HashBuffer(k.mArr.data(), k.mLen);

      //Get the result which should be the exchange hash value H
      UINT32 hLen = wc_HashGetDigestSize(mHashType);
      std::vector<Byte> h(hLen);
      ret = wc_HashFinal(&mHash, mHashType, h.data());
      if (ret != 0)
      {
        return false;
      }

      //Now we can verify our exchange hash with the server's signature
      {
        auto iter = signature.begin();

        //Size of signature name
        UINT32 sigNameLen = 0;
        sigNameLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        std::string sigName;
        sigName.assign((char*)&(*iter), sigNameLen);
        iter += sigNameLen;

        ret = wc_SignatureVerify( mHashType, WC_SIGNATURE_TYPE_RSA_W_ENC,
                                  h.data(), hLen, (Byte*)&(*iter), (signature.end() - iter),
                                  &key, sizeof(key));
        if (ret != 0)
        {
          return false;
        }
      }

      return false;
    }
};

TKEXHandler KEX::CreateDH(DHGroups group)
{
  std::shared_ptr<DH_KEXHandler> pHandler = std::make_shared<DH_KEXHandler>();

  pHandler->Init(group);

  return pHandler;
}
