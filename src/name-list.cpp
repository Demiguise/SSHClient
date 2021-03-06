#include "name-list.h"
#include <algorithm>

using namespace SSH;

NameList::NameList()
  : mList("")
  , mNumNames(0)
{}

void NameList::Init(const Byte* pBuf, const int numBytes)
{
  mList.assign((char*)pBuf, numBytes);
  if (!mList.empty())
  {
    mNumNames = std::count(mList.begin(), mList.end(), ',') + 1;
  }
  else
  {
    mNumNames = 0;
  }
}

NameList& NameList::operator+= (std::string newName)
{
  Add(newName);
  return *this;
}

void NameList::Add(std::string newName)
{
  if (mNumNames > 0)
  {
    mList += ',';
  }

  mList += newName;
  mNumNames++;
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

  return view.substr(startPos, (endPos - startPos));
}

std::string SelectBestMatch(const NameList& client, const NameList& server)
{
  return "";
}
