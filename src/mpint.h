#ifndef __MPINT_H__
#define __MPINT_H__

#include "ssh.h"
#include <array>

namespace SSH
{
  constexpr int sMAX_KEX_KEY_SIZE = (8192 / 8);

  class MPInt
  {
  private:
    using TData = std::array<Byte, sMAX_KEX_KEY_SIZE + 1>; //+1 in case of padding
    using TIter = TData::iterator;

    TData mArr;
    UINT32 mLen = 0;
    bool mPadding = false;

  public:
    MPInt() = default;
    ~MPInt() = default;

    /*
      Copies data for an MPint to the internal buffer.
      Expects that this is the raw MPInt data without the UINT32 len field preceeding it.
    */
    void Init(const Byte* pBuf, const int bufLen);

    Byte* Data() { return mArr.data(); }
    UINT32 Len() { return mLen; }
    void SetLen(UINT32 newLen) { mLen = newLen; }

    /*
      Use after filling the MPInt's data to handle all padding operations.
      Should be used when generating MPInts and not when reading them from buffers.
    */
    void Pad();
  };
}

#endif //~__MPINT_H__
