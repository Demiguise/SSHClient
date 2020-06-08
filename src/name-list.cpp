#include "name-list.h"
#include <algorithm>

using namespace SSH;

void NameList::Init(const Byte* pBuf, const int numBytes)
{
  mList.assign((char*)pBuf, numBytes);
  mNumNames = std::count(mList.begin(), mList.end(), ',') + 1;
}
