#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "ssh.h"
#include "name-list.h"

namespace SSH
{
  enum class EncryptionHandlers
  {
    None,
    AES128_CTR
  };

  class IEncryptionHandler
  {
  public:
    virtual ~IEncryptionHandler() {}
    virtual void SetKey(const Byte* pBuf, const int bufLen) = 0;
    virtual bool Encrypt(const Byte* pBuf, const int bufLen) = 0;
    virtual bool Decrypt(const Byte* pBuf, const int bufLen) = 0;
  };

  using TEncryptHandler = std::shared_ptr<IEncryptionHandler>;

  namespace Crypto
  {
    void PopulateNamelist(NameList& list);

    TEncryptHandler Create(EncryptionHandlers handler);
  }
}

#endif //~__CRYPTO_H__
