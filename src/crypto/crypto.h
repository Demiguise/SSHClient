#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "ssh.h"
#include "name-list.h"
#include "key.hpp"

namespace SSH
{
  enum class CryptoHandlers
  {
    None,
    AES128_CTR
  };

  class ICryptoHandler
  {
  public:
    virtual ~ICryptoHandler() {}
    virtual bool SetKey(const Key& encKey, const Key& ivKey) = 0;
    virtual bool Encrypt(Byte* pBuf, const int bufLen) = 0;
    virtual bool Decrypt(Byte* pBuf, const int bufLen) = 0;
    virtual CryptoHandlers Type() = 0;
    virtual UINT32 BlockLen() = 0;
  };

  using TCryptoHandler = std::shared_ptr<ICryptoHandler>;

  namespace Crypto
  {
    void PopulateNamelist(NameList& list);

    TCryptoHandler Create(CryptoHandlers handler);
  }
}

#endif //~__CRYPTO_H__
