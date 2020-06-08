#ifndef __NAME_LIST_H__
#define __NAME_LIST_H__

#include <string>

#include "ssh.h"

namespace SSH
{
  class NameList
  {
  private:
    std::string mList;
    int mNumNames;

  public:
    NameList() = default;

    void Init(const Byte *pBuf, const int numBytes);
  };
}

#endif //~__NAME_LIST_H__

