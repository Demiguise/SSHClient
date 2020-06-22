#include "debug.h"
#include "endian.h"
#include <stdio.h>
#include <fstream>
#include <iomanip>

using namespace SSH;

void SSH::DumpBufferToDisk(std::string fileName, const Byte* pBuf, const UINT32 bufLen)
{
  UINT32 fullLen = bufLen + sizeof(UINT32);
  UINT32 nBufLen = swap_endian<uint32_t>(bufLen);
  std::ofstream ofs("dump/" + fileName);

  constexpr int columnLimit = 16;
  ofs << "Name: " << fileName << std::endl;
  ofs << "Len: " << fullLen << std::endl;
  ofs << "Bytes : [" << std::endl << '\t' << std::hex;

  int writeIdx = 0;

  //Output the length field like a regular buffer for SSH
  char* pLen = (char*)&nBufLen;
  ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pLen[0] << ", "; writeIdx++;
  ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pLen[1] << ", "; writeIdx++;
  ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pLen[2] << ", "; writeIdx++;
  ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pLen[3] << ", "; writeIdx++;

  //Now print each byte in hexadecimal form
  for (int i = 0; i < bufLen ; ++i, ++writeIdx)
  {
    if ((i != 0 ) && ((writeIdx % columnLimit) == 0))
    {
      ofs << std::endl << '\t';
    }

    ofs << "0x" << std::setfill('0') << std::setw(2) << (int)pBuf[i] << ", ";
  }

  ofs << std::endl << "]" << std::endl;
}
