#include "crypto.h"

#define WOLFCRYPT_ONLY
#define WOLFSSL_LIB
#define WOLFSSL_AES_COUNTER
#include <IDE/WIN10/user_settings.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <string.h> //memset

using namespace SSH;

void Crypto::PopulateNamelist(NameList& list)
{
  list.Add("aes128-ctr");
}

class None_CryptoHandler : public ICryptoHandler
{
public:
  None_CryptoHandler() = default;

  virtual bool SetKey(const Key& key, const Key& ivKey) override
  {
    return true;
  }

  virtual bool Encrypt(Byte* pBuf, const int bufLen) override
  {
    return true;
  }

  virtual bool Decrypt(Byte* pBuf, const int bufLen) override
  {
    return true;
  }
  virtual CryptoHandlers Type() override { return CryptoHandlers::None; }
  virtual UINT32 BlockLen() override { return 0; }
};

class AES128_CTR_CryptoHandler : public ICryptoHandler
{
private:
  Aes mKey;

public:
  AES128_CTR_CryptoHandler()
  {
    memset(&mKey, 0, sizeof(Aes));
  }

  ~AES128_CTR_CryptoHandler()
  {
    memset(&mKey, 0, sizeof(Aes));
  }

  virtual bool SetKey(const Key& encKey, const Key& ivKey) override
  {
    int ret = wc_AesSetKey(&mKey, encKey.Data(), encKey.Len(), ivKey.Data(), AES_ENCRYPTION); //TODO check if this DIR is important
    if (ret != 0)
    {
      return false;
    }

    return true;
  }

  virtual bool Encrypt(Byte* pBuf, const int bufLen) override
  {
    //AES uses encrypt call for both encryption and decryption
    int ret = wc_AesCtrEncrypt(&mKey, pBuf, pBuf, bufLen);
    if (ret != 0)
    {
      return false;
    }

    return true;
  }

  virtual bool Decrypt(Byte* pBuf, const int bufLen) override
  {
    //AES uses encrypt call for both encryption and decryption
    int ret = wc_AesCtrEncrypt(&mKey, pBuf, pBuf, bufLen);
    if (ret != 0)
    {
      return false;
    }

    return true;
  }
  virtual CryptoHandlers Type() override { return CryptoHandlers::AES128_CTR; }
  virtual UINT32 BlockLen() override { return AES_BLOCK_SIZE; }
};

TCryptoHandler Crypto::Create(CryptoHandlers handler)
{
  switch(handler)
  {
    case CryptoHandlers::AES128_CTR:
      return std::make_shared<AES128_CTR_CryptoHandler>();
    default:
      return std::make_shared<None_CryptoHandler>();
  }
}
