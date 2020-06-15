#ifndef __MPINT_H__
#define __MPINT_H__

#include "ssh.h"

template<size_t size>
class MPInt
{
private:
  using TData = std::array<SSH::Byte, size>;

public:
  TData mArr;
  UINT32 mLen = 0;
  bool mPadding = false;

  //Handles the padding
  void Prepare()
  {
    typename TData::iterator iter = mArr.begin();

    //Find the first non zero byte
    for (; iter != mArr.end(); ++iter)
    {
      if (*iter != 0x00)
      {
        break;
      }
    }

    //Check for padding
    if (*iter & 0x80)
    {
      mPadding = true;
    }

    if (mPadding)
    {
      iter--;
      mPadding = false;
    }

    if (iter > mArr.begin())
    {
      mLen -= (iter - mArr.begin());
      std::move(iter, mArr.end(), mArr.begin());
    }
  }
};

#endif //~__MPINT_H__
