#ifndef __MPINT_H__
#define __MPINT_H__

#include "ssh.h"
#include <array>

#define MAX_KEX_KEY_SZ (8192 / 8)

class MPInt
{
private:
  using TData = std::array<SSH::Byte, MAX_KEX_KEY_SZ+1>; //+1 in case of padding
  using TIter = TData::iterator;

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
      if (mPadding)
      {
        /*
          If we have padding we should increase the size of this MPInt
          and move the begin iterator forward so we can just set the first byte to zero.
          This saves callers from having to manage padding themselves.
        */
        mLen++;

        *iterBegin = 0x00;
        iterBegin++;
      }

      std::move(iter, iterEnd, iterBegin);
    }
  }
};

#endif //~__MPINT_H__
