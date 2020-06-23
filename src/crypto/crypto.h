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


  namespace Crypto
  {
    void PopulateNamelist(NameList& list);
  }
}

#endif //~__CRYPTO_H__
