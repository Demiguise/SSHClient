#include "ssh_impl.h"
#include "packets.h"
#include "endian.h"
#include "constants.h"

#include <stdarg.h>
#include <future>
#include <array>
#include <cstring>
#include <algorithm>

using namespace SSH;

//Define the CR/LF bytes here for readability later on
constexpr char CRbyte = 0x0D;
constexpr char LFbyte = 0x0A;

/*
  A buffer that aims at making sure ALL data within it is correctly
  scrubbed after it goes out of scoped.
*/
template<typename T, std::size_t size>
class SecureBuffer
{
private:
  std::array<T, size> mArr;
public:
  SecureBuffer()
  {}

  ~SecureBuffer()
  {
    //TODO: This NEEDS to be secure
    memset(mArr.data(), 0, size);
  }

  T* Buffer() { return mArr.data(); }
  size_t Length() { return size; }
};

Client::Impl::Impl(ClientOptions options, TCtx ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.recv)
  , mOnRecvFunc(options.onRecv)
  , mCtx(ctx)
  , mState(State::Idle)
  , mStage(Stage::Null)
  , mLogFunc(options.log)
  , mLogLevel(options.logLevel)
{
}

Client::Impl::~Impl()
{
}

void Client::Impl::Log(LogLevel level, const std::string frmt, ...)
{
  char buffer[Impl::sMaxLogLength];
  int bytesWritten = 0;

  if (mLogLevel < level)
  {
    return;
  }

  va_list args;
  va_start(args, frmt);
  bytesWritten = vsnprintf(buffer, Impl::sMaxLogLength, frmt.c_str(), args);
  va_end(args);

  //Add the null terminator.
  buffer[bytesWritten] = '\0';

  mLogFunc(buffer);
}

void Client::Impl::LogBuffer(LogLevel level, const std::string bufferName, const Byte* pBuf, const int bufLen)
{
  std::unique_ptr<char[]> pLogBuf;
  int bytesWritten = 0;
  constexpr int extraChars = 4; //[...]\n...\0
  constexpr int columnLimit = 16;

  if (mLogLevel < level)
  {
    return;
  }

  const int totalBytes = (bufLen * 3) + bufferName.length() + extraChars + (bufLen / columnLimit); //Each character is actually "XX "
  pLogBuf = std::make_unique<char[]>(totalBytes);
  if (pLogBuf == nullptr)
  {
    //Failed to allocate
    return;
  }

  //Output the name of the buffer we were passed
  bytesWritten = sprintf(pLogBuf.get(), "[%s]", bufferName.c_str());

  //Now print each byte in hexadecimal form
  for (int i = 0; i < bufLen ; ++i)
  {
    if ((i % columnLimit) == 0)
    {
      bytesWritten += sprintf(pLogBuf.get() + bytesWritten, "\n");
    }

    bytesWritten += sprintf(pLogBuf.get() + bytesWritten, "%.2X ", pBuf[i]);
  }

  //Ensure we start a new line and end the string
  pLogBuf[bytesWritten++] = '\0';

  mLogFunc(pLogBuf.get());
}

TResult Client::Impl::Send(const Byte* pBuf, const int bufLen)
{
  auto sentBytes = mSendFunc(mCtx, pBuf, bufLen);
  if (!sentBytes.has_value())
  {
    Log(LogLevel::Warning, "Failed to send %d bytes", bufLen);
    return {};
  }

  Log(LogLevel::Debug, "Successfully sent %d/%d bytes", sentBytes, bufLen);
  return sentBytes;
}

void Client::Impl::Poll()
{
  while (mState != State::Disconnected)
  {
    //Populate our buffer with data from the underlying transport
    SecureBuffer<unsigned char, 1024> buf;
    auto recievedBytes = mRecvFunc(mCtx, buf.Buffer(), buf.Length());

    if (!recievedBytes.has_value())
    {
      //No data received, nothing to do.
      continue;
    }

    /*
      We received a number of bytes from the transport, simply hand them over
      to the implementation to handle.
    */
    Log(LogLevel::Info, "Recieved %d bytes from remote!", recievedBytes.value());

    HandleData(buf.Buffer(), recievedBytes.value());
  }
}

void Client::Impl::HandleData(const Byte* pBuf, const int bufLen)
{
  if (mState == State::Idle ||
      mState == State::Disconnected)
  {
    Log(LogLevel::Error, "Recieved %d bytes of data from remote without being connected.", bufLen);
    return;
  }

  switch (mStage)
  {
    case Stage::Null:
    {
      Log(LogLevel::Error, "Attempted to perform handshake for a NULL stage.");
      return;
    }
    case Stage::ServerIdent:
    {
      HandleServerIdent(pBuf, bufLen);
      return;
    }
    case Stage::ServerKEX:
    {
      PerformKEX(pBuf, bufLen);
      return;
    }
    default:
    {
      Log(LogLevel::Warning, "Unhandled data for (%s) state", StateToString(mState));
      Disconnect();
      return;
    }
  }
}

int Client::Impl::ParseNameList(NameList& list, const Byte* pBuf)
{
  UINT32 nameLen = swap_endian<uint32_t>(*(uint32_t*)pBuf);
  list.Init(pBuf + sizeof(UINT32), nameLen);
  return nameLen + sizeof(UINT32);
}

void Client::Impl::HandleServerIdent(const Byte* pBuf, const int bufLen)
{
  std::string serverIdent;
  constexpr int minBufLen = 5;   //SSH-\LF
  constexpr int maxBufLen = 255; //RFC4253#section-4.2
  if (bufLen < minBufLen || bufLen > maxBufLen)
  {
    Log(LogLevel::Error, "Malformed ServerIdent of %d bytes. MUST be > 6 && < 255", bufLen);
    return;
  };

  /*
    Although the SSH RFC REQUIRES servers to send <CR><LF>, some only send <LF>.
    To maintain compatibility, we only check for <LF> bytes and warn when the <CR>
    is not present.
  */
  for (int i = 0; i < bufLen; ++i)
  {
    if (pBuf[i] == LFbyte)
    {
      if (pBuf[i - 1] != CRbyte)
      {
        Log(LogLevel::Warning, "ServerIdent did not use RFC standard <CR><LR> ending.");
      }

      //Found the ending byte
      serverIdent.assign((char *)pBuf, i);
    }
  }

  if (serverIdent.empty())
  {
    Log(LogLevel::Info, "Unable to parse ServerIdent");
    LogBuffer(LogLevel::Debug, "ServerIdent", pBuf, bufLen);
  }
  else
  {
    Log(LogLevel::Info, "ServerIdent [%d]: %s", serverIdent.length(), serverIdent.c_str());
  }

  mStage = Stage::ServerKEX;
  return;
}

void Client::Impl::PerformKEX(const Byte* pBuf, const int bufLen)
{
  int bytesRemaining = bufLen;

  IPacket* pPacket = nullptr;
  if (!mQueue.empty())
  {
    pPacket = mQueue.back();
    int bytesConsumed = pPacket->Consume(pBuf, bufLen);
    bytesRemaining -= bytesConsumed;
    Log(LogLevel::Info, "Packet consumed an additional [%d] bytes", bytesConsumed);

    if (pPacket->Ready())
    {
      Log(LogLevel::Info, "Queued packet is now ready!");
    }
    else
    {
      Log(LogLevel::Info, "Still waiting on more bytes for this packet");
      return;
    }
  }
  else
  {
    if (bytesRemaining < 4)
    {
      Log(LogLevel::Error, "Not enough bytes for packet");
      return;
    }

    UINT32 packetLen = GetPacketLength(pBuf);
    IPacket *pPacket = GetPacket(packetLen);
    if (!pPacket)
    {
      Log(LogLevel::Error, "Failed to allocate a packet!");
      return;
    }

    if (!pPacket->InitFromBuffer(pBuf, std::min(bytesRemaining, (int)packetLen)))
    {
      Log(LogLevel::Error, "Failed to initalise packet");
    }

    if (bytesRemaining < packetLen)
    {
      //We have to wait for more data, pop this packet into the queue
      Log(LogLevel::Debug, "Queuing packet as we are waiting on [%d] bytes.", (packetLen - bytesRemaining));
      mQueue.push(pPacket);
      return;
    }
  }

  switch (mStage)
  {
    case Stage::ServerKEX:
    {
      const Byte* pKexIter = pPacket->Payload();

      //Verify this is a KEX packet
      if ((*pKexIter) != SSH_MSG::KEXINIT)
      {
        return;
      }
      pKexIter += sizeof(Byte);

      //Skip 16 bytes of random data
      pKexIter += cKexCookieLength;

      pKexIter += ParseNameList(mKex.mAlgorithms.mKex, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mServerHost, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mEncryption.mClientToServer, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mEncryption.mServerToClient, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mMAC.mClientToServer, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mMAC.mServerToClient, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mCompression.mClientToServer, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mCompression.mServerToClient, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mLanguages.mClientToServer, pKexIter);
      pKexIter += ParseNameList(mKex.mAlgorithms.mLanguages.mServerToClient, pKexIter);

      //Now we can send the client KEXData
      KEXData clientData;
      int requiredSize =  sizeof(Byte) +
                          cKexCookieLength +
                          clientData.mAlgorithms.mKex.Len() +
                          clientData.mAlgorithms.mServerHost.Len() +
                          clientData.mAlgorithms.mEncryption.mClientToServer.Len() +
                          clientData.mAlgorithms.mEncryption.mServerToClient.Len() +
                          clientData.mAlgorithms.mMAC.mClientToServer.Len() +
                          clientData.mAlgorithms.mMAC.mServerToClient.Len() +
                          clientData.mAlgorithms.mCompression.mClientToServer.Len() +
                          clientData.mAlgorithms.mCompression.mServerToClient.Len() +
                          clientData.mAlgorithms.mLanguages.mClientToServer.Len() +
                          clientData.mAlgorithms.mLanguages.mServerToClient.Len() +
                          sizeof(Byte) +
                          sizeof(UINT32);

      IPacket* pClientDataPacket = GetPacket(requiredSize);

      pPacket->Write((Byte)SSH_MSG::KEXINIT);

      Byte cookie[cKexCookieLength]; //TODO: Randomize this
      pPacket->Write(cookie, sizeof(cookie));

      pPacket->Write(clientData.mAlgorithms.mKex.Str());
      pPacket->Write(clientData.mAlgorithms.mServerHost.Str());
      pPacket->Write(clientData.mAlgorithms.mEncryption.mClientToServer.Str());
      pPacket->Write(clientData.mAlgorithms.mEncryption.mServerToClient.Str());
      pPacket->Write(clientData.mAlgorithms.mMAC.mClientToServer.Str());
      pPacket->Write(clientData.mAlgorithms.mMAC.mServerToClient.Str());
      pPacket->Write(clientData.mAlgorithms.mCompression.mClientToServer.Str());
      pPacket->Write(clientData.mAlgorithms.mCompression.mServerToClient.Str());
      pPacket->Write(clientData.mAlgorithms.mLanguages.mClientToServer.Str());
      pPacket->Write(clientData.mAlgorithms.mLanguages.mServerToClient.Str());

      pPacket->Write((Byte)false); //first_kex_packet_follows
      pPacket->Write(0); //Reserved UINT32

      return;
    }
    default:
    {
      Log(LogLevel::Error, "Unhandled stage");
      Disconnect();
      return;
    }
  }
}

void Client::Impl::Connect(const std::string pszUser)
{
  mState = State::Connecting;

  Log(LogLevel::Info, "Beginning to connect with user %s", pszUser.c_str());

  Log(LogLevel::Debug, "Starting poll async call");
  auto fut = std::async(std::launch::async, &Impl::Poll, this);

  Byte buf[512];
  int bytesWritten = snprintf((char*)buf, sizeof(buf), "SSH-2.0-billsSSH_3.6.3q3");
  buf[bytesWritten++] = CRbyte;
  buf[bytesWritten++] = LFbyte;

  mStage = Stage::ServerIdent;

  Send(buf, bytesWritten);
}

void Client::Impl::Disconnect()
{
  Log(LogLevel::Info, "Disconnecting client");
  mState = State::Disconnected;
  mStage = Stage::Null;
}
