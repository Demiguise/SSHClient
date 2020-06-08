#include "name-list.h"
#include <algorithm>

using namespace SSH;

void NameList::Init(const Byte* pBuf, const int numBytes)
{
  mList.assign((char*)pBuf, numBytes);
  mNumNames = std::count(mList.begin(), mList.end(), ',') + 1;
}

std::string_view NameList::operator[](const int n)
{
  return Get(n);
}

std::string_view NameList::Get(const int n)
{
  if (n < 0 || n > mNumNames)
  {
    return std::string_view();
  }

  std::string_view view = mList;

  int startPos = 0;
  int endPos = view.find(',');

  for (int i = 0; i < n; ++i)
  {
    startPos = endPos + 1;
    endPos = view.find(',', startPos);
  }

  auto newView = view.substr(startPos, (endPos - startPos));
  return newView;
}
