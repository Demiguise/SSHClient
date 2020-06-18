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
  void Prepare();
};

#endif //~__MPINT_H__
