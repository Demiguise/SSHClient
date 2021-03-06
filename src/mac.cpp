#include "mac.h"
#include "endian.h"
#include "packets.h"

#define WOLFCRYPT_ONLY
#define WOLFSSL_LIB
#define WOLFSSL_AES_COUNTER
#include <IDE/WIN10/user_settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

using namespace SSH;

void MAC::PopulateNamelist(NameList& list)
{
  list.Add("hmac-sha2-256");
}

class None_MACHandler : public IMACHandler
{
public:
  None_MACHandler() = default;

  virtual UINT32 Len() override
  {
    return 0;
  }

  virtual bool SetKey(const Key& macKey) override
  {
    return true;
  }

  virtual bool Create(const Packet* const pPacket, Byte* pOutMAC) override
  {
    return true;
  }

  virtual bool Verify(const Packet* const pPacket) override
  {
    return true;
  }

  virtual MACHandlers Type() override { return MACHandlers::None; }
};

class HMAC_SHA2_256_MACHandler : public IMACHandler
{
private:
  Key mMACKey;
public:
  HMAC_SHA2_256_MACHandler() = default;

  virtual UINT32 Len() override
  {
    return MACLen();
  }

  static UINT32 MACLen()
  {
    return WC_SHA256_DIGEST_SIZE;
  }

  virtual bool SetKey(const Key& macKey) override
  {
    mMACKey = macKey;
    return true;
  }

  virtual bool Create(const Packet* const pPacket, Byte* pOutMAC) override
  {
    Hmac hmac;
    int ret = wc_HmacInit(&hmac, nullptr, INVALID_DEVID);
    if (ret != 0)
    {
      return false;
    }

    ret = wc_HmacSetKey(&hmac, WC_SHA256, mMACKey.Data(), mMACKey.Len());
    if (ret != 0)
    {
      return false;
    }
    //First we hash the network ordered sequence number for the packet
    UINT32 seqNumber = swap_endian<uint32_t>(pPacket->GetSequenceNumber());
    ret = wc_HmacUpdate(&hmac, (Byte*)&seqNumber, sizeof(UINT32));
    if (ret != 0)
    {
      return false;
    }

    //Now we hash the entire unencrypted packet, including the packet length field
    ret = wc_HmacUpdate(&hmac, pPacket->Begin(), pPacket->PacketLen() + sizeof(UINT32));
    if (ret != 0)
    {
      return false;
    }

    //Now we can output do the MAC field
    ret = wc_HmacFinal(&hmac, pOutMAC);
    if (ret != 0)
    {
      return false;
    }

    return true;
  }

  virtual bool Verify(const Packet* const pPacket) override
  {
    TByteString MAC(Len());
    Create(pPacket, MAC.data());

    return (memcmp(MAC.data(), pPacket->MAC(), Len()) == 0);
  }

  virtual MACHandlers Type() override { return MACHandlers::HMAC_SHA2_256; }
};

TMACHandler MAC::Create(MACHandlers handler)
{
  switch (handler)
  {
    case MACHandlers::HMAC_SHA2_256:
      return std::make_shared<HMAC_SHA2_256_MACHandler>();
    default:
    case MACHandlers::None:
      return std::make_shared<None_MACHandler>();
  }
}

UINT32 MAC::Len(MACHandlers handler)
{
  switch (handler)
  {
    case MACHandlers::HMAC_SHA2_256:
      return HMAC_SHA2_256_MACHandler::MACLen();
    default:
    case MACHandlers::None:
      return 0;
  }
}
