#include "mpint.h"

using namespace SSH;

MPInt::MPInt()
{
  std::fill(mArr.begin(), mArr.end(), 0);
}

void MPInt::Init(const Byte* pBuf, const int bufLen)
{
  if (bufLen > sMAX_KEX_KEY_SIZE)
  {
    return;
  }

  memcpy(mArr.data(), pBuf, bufLen);
  mLen = bufLen;
}

void MPInt::Pad()
{
  TIter iter = mArr.begin();
  TIter iterBegin = mArr.begin();
  TIter iterEnd = mArr.end();
  bool bRequiresPadding = false;

  if (mLen == 0)
  {
    //A zero sized MPInt has no work to do
    return;
  }

  //Find the first non zero byte, in case writer prepended any NULL data.
  for (; iter != iterEnd; ++iter)
  {
    if (*iter != 0x00)
    {
      break;
    }
  }

  //Check if we require padding on the first non zero byte
  if (*iter & 0x80)
  {
    bRequiresPadding = true;
  }

  if (bRequiresPadding)
  {
    //We must prepend this sequence with a null byte.
    //Increase the size by one so users don't need to care about the underlying change.
    mLen++;
    TIter sequenceEnd = iter + mLen;
    if (iter > iterBegin)
    {
      /*
        If the iterator is past the beginning (and thus contains preceeding null bytes)
        we can simply move the iterator back one space to accomodate the new null byte.
      */
      iter--;

      /*
        If the iterator is still past the beginning of the sequence then we must move the whole sequence
        back to the beginning.
      */
      if (iter > iterBegin)
      {
        std::move(iter, sequenceEnd, iterBegin);
      }
    }
    else
    {
      /*
        If the iterator is at the beginning of the sequence then we must move the whole sequence ahead one byte.
      */
      std::move_backward(iter, sequenceEnd, sequenceEnd + 1);
      *iterBegin = 0x00;
    }
  }
}
