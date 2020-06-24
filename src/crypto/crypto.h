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

  class Key
  {
    using TKeyData = std::vector<Byte>;
    TKeyData mData;
    UINT32 mLen = 0;
  public:
    Key() = default;
    ~Key();

    const Byte* Data() const { return mData.data(); }
    Byte* Data() { return mData.data(); }
    UINT32 Len() const { return mLen; }
    void SetLen(UINT32 newLen)
    {
      mData.resize(newLen);
      mLen = newLen;
    }
  };

  class ICryptoHandler
  {
  public:
    virtual ~ICryptoHandler() {}
    virtual bool SetKey(const Key& encKey, const Key& ivKey) = 0;
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
