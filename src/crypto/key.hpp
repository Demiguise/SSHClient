#ifndef __KEY_H__
#define __KEY_H__

#include "ssh.h"

namespace SSH
{
  class Key
  {
    using TKeyData = std::vector<Byte>;
    TKeyData mData;
    UINT32 mLen = 0;
  public:
    Key() = default;
    ~Key()
    {
      //Ensure the key is nuked from memory.
      //TODO: Check this is not removed via optimisation
      std::fill(mData.begin(), mData.end(), 0);
    }

    const Byte* Data() const { return mData.data(); }
    Byte* Data() { return mData.data(); }
    UINT32 Len() const { return mLen; }
    void SetLen(UINT32 newLen)
    {
      mData.resize(newLen);
      mLen = newLen;
    }
  };
}

#endif //~__KEY_H__
