#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "ssh.h"
#include "name-list.h"

namespace SSH
{
  enum class CryptoHandlers
  {
    None,
    AES128_CTR
  };

  struct Key
  {
  public:
    Key() = default;
    ~Key();

    using TKeyData = std::vector<Byte>;
    TKeyData mData;
    UINT32 mLen;
  };

  class ICryptoHandler
  {
  public:
    virtual ~ICryptoHandler() {}
    virtual bool SetKey(const Key& key) = 0;
    virtual bool Encrypt(Byte* pBuf, const int bufLen) = 0;
    virtual bool Decrypt(Byte* pBuf, const int bufLen) = 0;
    virtual CryptoHandlers Type() = 0;
  };

  using TCryptoHandler = std::shared_ptr<ICryptoHandler>;

  namespace Crypto
  {
    void PopulateNamelist(NameList& list);

    TCryptoHandler Create(CryptoHandlers handler);
  }
}

#endif //~__CRYPTO_H__
