#ifndef __MPINT_H__
#define __MPINT_H__

#include "ssh.h"

template<size_t size>
class MPInt
{
private:
  using TData = std::array<SSH::Byte, size>;
  using TIter = typename TData::iterator;

public:
  TData mArr;
  UINT32 mLen = 0;
  bool mPadding = false;

  //Handles the padding
  void Prepare()
  {
    TIter iter = mArr.begin();
    TIter iterEnd = mArr.end();
    TIter iterBegin = mArr.begin();

    //Find the first non zero byte
    for (; iter != iterEnd; ++iter)
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

    if (iter != iterBegin && mPadding)
    {
      iter--;
      mPadding = false;
    }

    if (iter > iterBegin)
    {
      mLen -= (iter - iterBegin);
      std::move(iter, iterEnd, iterBegin);
    }
  }
};

#endif //~__MPINT_H__
