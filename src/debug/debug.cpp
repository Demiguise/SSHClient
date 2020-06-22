#include "debug.h"
#include <stdio.h>
#include <fstream>
#include <iomanip>

using namespace SSH;

void SSH::DumpBufferToDisk(std::string fileName, const Byte* pBuf, const int bufLen)
{
  std::ofstream ofs("dump/" + fileName);

  constexpr int columnLimit = 16;
  ofs << "Name: " << fileName << std::endl;
  ofs << "Len: " << bufLen << std::endl;
  ofs << "Bytes : [" << std::endl << '\t' << std::hex;

  //Now print each byte in hexadecimal form
  for (int i = 0; i < bufLen ; ++i)
  {
    if ((i != 0 ) && ((i % columnLimit) == 0))
    {
      ofs << std::endl << '\t';
    }

    ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pBuf[i] << ", ";
  }

  ofs << std::endl << "]" << std::endl;
}
