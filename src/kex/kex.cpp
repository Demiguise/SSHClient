#include "kex.h"
#include "dh_groups.h"
#include "constants.h"
#include "mpint.h"
#include "endian.h"

//Temporarily include this win10 user settings, otherwise we encounter stack smashing
#define WOLFCRYPT_ONLY
#include <IDE/WIN10/user_settings.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/signature.h>

using namespace SSH;

#ifdef _DEBUG
#include "debug/debug.h"
#endif

class DH_KEXHandler : public SSH::IKEXHandler
{
  private:
    DhKey mPrivKey;
    WC_RNG mRNG;
    wc_HashAlg mHash;
    wc_HashType mHashType;

    Key mH;
    MPInt mK;

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

      UINT32 xLen = 0;
      UINT32 eLen = 0;

      ret = wc_DhGenerateKeyPair(&mPrivKey, &mRNG,
                                 mHandshake.x.Data(), &xLen,
                                 mHandshake.e.Data(), &eLen);
      if (ret != 0)
      {
        return false;
      }

      mHandshake.x.SetLen(xLen);
      mHandshake.e.SetLen(eLen);

      mHandshake.x.Pad();
      mHandshake.e.Pad();

      DUMP_BUFFER("x", mHandshake.x.Data(), mHandshake.x.Len());
      DUMP_BUFFER("e", mHandshake.e.Data(), mHandshake.e.Len());

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

    TPacket CreateInitPacket(PacketStore& store) override
    {
      mHandshake.e.Pad();

      //Calculate the length of the packet
      int packetLen = sizeof(Byte) + //MSG_ID
                      sizeof(UINT32) + //Length
                      mHandshake.e.Len();

      TPacket pPacket = store.Create(packetLen, PacketType::Write);

      pPacket->Write((Byte)SSH_MSG::KEXDH_INIT);
      pPacket->Write(mHandshake.e.Data(), mHandshake.e.Len());

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

      TByteString keyCerts;
      MPInt f;
      TByteString signature;

      pDHReply->Read(keyCerts);
      pDHReply->Read(f);
      pDHReply->Read(signature);

      //Hash identifiers
      HashBuffer((Byte*)client.mIdent.c_str(), client.mIdent.length());
      HashBuffer((Byte*)server.mIdent.c_str(), server.mIdent.length());

      DUMP_BUFFER("client_ident", (Byte*)client.mIdent.c_str(), client.mIdent.length());
      DUMP_BUFFER("server_ident", (Byte*)server.mIdent.c_str(), server.mIdent.length());

      //Hash KEXInit packets
      HashBuffer(client.mKEXInit->Payload(), client.mKEXInit->PayloadLen());
      HashBuffer(server.mKEXInit->Payload(), server.mKEXInit->PayloadLen());

      DUMP_BUFFER("client_kexInit", client.mKEXInit->Payload(), client.mKEXInit->PayloadLen());
      DUMP_BUFFER("server_kexInit", server.mKEXInit->Payload(), server.mKEXInit->PayloadLen());

      //Hash server's HostKey data (The entire buffer)
      HashBuffer(keyCerts.data(), keyCerts.size());

      DUMP_BUFFER("keyCerts", keyCerts.data(), keyCerts.size());

      //Hash MPInts e (client's) and f (server's)
      HashBuffer(mHandshake.e.Data(), mHandshake.e.Len());
      HashBuffer(f.Data(), f.Len());

      DUMP_BUFFER("f", f.Data(), f.Len());

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

        e.Init(&(*iter), eLen);
        iter += eLen;

        UINT32 nLen = 0;
        nLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        n.Init(&(*iter), nLen);
        iter += nLen;

        ret = wc_RsaPublicKeyDecodeRaw(n.Data(), n.Len(), e.Data(), e.Len(), &key);
        if (ret != 0)
        {
          return false;
        }
      }
      //Generate shared secret K
      UINT32 kLen = 0;
      int ret = wc_DhAgree( &mPrivKey, mK.Data(), &kLen,
                            mHandshake.x.Data(), mHandshake.x.Len(),
                            f.Data(), f.Len());
      if (ret != 0)
      {
        return false;
      }

      //Hash shared secret (Ensuring we make sure the data is padded)
      mK.SetLen(kLen);
      mK.Pad();
      HashBuffer(mK.Data(), mK.Len());

      DUMP_BUFFER("k", mK.Data(), mK.Len());

      /*
        Get the result which should be the exchange hash value H.
        This is stored on the KEXHandler as the user may wish to
        grab it as the "SessionID" for this connection
      */
      UINT32 hLen = wc_HashGetDigestSize(mHashType);
      mH.SetLen(hLen);
      ret = wc_HashFinal(&mHash, mHashType, mH.Data());
      if (ret != 0)
      {
        return false;
      }

      DUMP_BUFFER("h", mH.Data(), mH.Len());

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

        UINT32 sigLen = 0;
        sigLen = swap_endian<uint32_t>(*(UINT32*)&(*iter));
        iter += sizeof(UINT32);

        UINT32 bytesRemaining = signature.end() - iter;

        ret = wc_SignatureVerify( mHashType, WC_SIGNATURE_TYPE_RSA_W_ENC,
                                  mH.Data(), mH.Len(), (Byte*)&(*iter), bytesRemaining,
                                  &key, sizeof(key));
        if (ret != 0)
        {
          return false;
        }
      }

      return true;
    }

    virtual Key GetSessionID() override
    {
      return mH;
    }

    virtual bool GenerateKey(Key& outKey, const Key& sessionID, const Byte keyID) override
    {
      int ret = 0;
      wc_HashAlg hash;

      ret = wc_HashInit(&hash, mHashType);
      if (ret != 0)
      {
        return false;
      }

      ret = wc_HashUpdate(&hash, mHashType, mK.Data(), mK.Len());
      if (ret != 0)
      {
        return false;
      }

      ret = wc_HashUpdate(&hash, mHashType, mH.Data(), mH.Len());
      if (ret != 0)
      {
        return false;
      }

      ret = wc_HashUpdate(&hash, mHashType, &keyID, sizeof(keyID));
      if (ret != 0)
      {
        return false;
      }

      ret = wc_HashUpdate(&hash, mHashType, sessionID.Data(), sessionID.Len());
      if (ret != 0)
      {
        return false;
      }

      int digestSize = wc_HashGetDigestSize(mHashType);
      ret = wc_HashFinal(&hash, mHashType, outKey.Data());
      if (ret != 0)
      {
        return false;
      }

      return true;
    }

    virtual UINT32 GetBlockSize()
    {
      return AES_BLOCK_SIZE;
    }

    virtual UINT32 GetKeySize()
    {
      return AES_BLOCK_SIZE;
    }
};

TKEXHandler KEX::CreateDH(DHGroups group)
{
  std::shared_ptr<DH_KEXHandler> pHandler = std::make_shared<DH_KEXHandler>();

  pHandler->Init(group);

  return pHandler;
}
