#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "ssh.h"

namespace SSH
{
  void DumpBufferToDisk(std::string fileName, const Byte* pBuf, const int bufLen);
}

#ifdef DBG_DUMP_BUFFER
#define DUMP_BUFFER(name, pBuf, bufLen) DumpBufferToDisk(name, pBuf, bufLen)
#else
#define DUMP_BUFFER(name, pBuf, bufLen)
#endif

#endif //~__DEBUG_H__
