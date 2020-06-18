#include "mpint.h"

void MPInt::Prepare()
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
