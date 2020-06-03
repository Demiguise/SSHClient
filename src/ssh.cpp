#include "ssh.h"

using namespace SSH;

Client::Client(TSendFunc sendFunc, TRecvFunc recvFunc, TCtx ctx)
  : mSendFunc(sendFunc)
  , mRecvFunc(recvFunc)
  , mCtx(ctx)
{

}

void Client::Send(const char* pBuf, const int bufLen)
{
  mSendFunc(mCtx, pBuf, bufLen);
}

void Client::Recv(const char* pBuf, const int bufLen)
{
  mRecvFunc(mCtx, pBuf, bufLen);
}
