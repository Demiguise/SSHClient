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

class NoneHandler : public ICryptoHandler
{
public:
  NoneHandler() = default;

  virtual bool SetKey(const Byte* pKeyBuf, const int keyLen) override
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
};

class AES128_CTRHandler : public ICryptoHandler
{
private:
  Aes mKey;

public:
  AES128_CTRHandler()
  {
    memset(&mKey, 0, sizeof(Aes));
  }

  ~AES128_CTRHandler()
  {
    memset(&mKey, 0, sizeof(Aes));
  }

  virtual bool SetKey(const Byte* pKeyBuf, const int keyLen) override
  {
    int ret = wc_AesGcmSetKey(&mKey, pKeyBuf, keyLen);
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
};

TCryptoHandler Crypto::Create(CryptoHandlers handler)
{
  switch(handler)
  {
    case CryptoHandlers::AES128_CTR:
      return std::make_shared<AES128_CTRHandler>();
    default:
      return std::make_shared<NoneHandler>();
  }
}
