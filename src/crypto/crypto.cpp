#include "crypto.h"

using namespace SSH;

void Crypto::PopulateNamelist(NameList& list)
{
  list.Add("aes128-ctr");
}

class NoneHandler : public IEncryptionHandler
{
public:
  NoneHandler() = default;

  virtual void SetKey(const Byte* pBuf, const int bufLen) override
  {}

  virtual bool Encrypt(const Byte* pBuf, const int bufLen) override
  {
    return true;
  }

  virtual bool Decrypt(const Byte* pBuf, const int bufLen) override
  {
    return true;
  }
};

class AES128_CTRHandler : public IEncryptionHandler
{
public:
  AES128_CTRHandler() = default;

  virtual void SetKey(const Byte* pBuf, const int bufLen) override
  {

  }

  virtual bool Encrypt(const Byte* pBuf, const int bufLen) override
  {
    return true;
  }

  virtual bool Decrypt(const Byte* pBuf, const int bufLen) override
  {
    return true;
  }
};

TEncryptHandler Crypto::Create(EncryptionHandlers handler)
{
  switch(handler)
  {
    case EncryptionHandlers::AES128_CTR:
      return std::make_shared<AES128_CTRHandler>();
    default:
      return std::make_shared<NoneHandler>();
  }
}
