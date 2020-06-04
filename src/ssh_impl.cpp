#include "ssh_impl.h"

#include <stdarg.h>
#include <future>
#include <array>
#include <cstring>

using namespace SSH;

//Define the CR/LF bytes here for readability later on
constexpr char CRbyte = 0x0D;
constexpr char LFbyte = 0x0A;

/*
  A buffer that aims at making sure ALL data within it is correctly
  scrubbed after it goes out of scoped.
*/
template<std::size_t size>
class SecureBuffer
{
private:
  std::array<char, size> mArr;
public:
  SecureBuffer()
  {}

  ~SecureBuffer()
  {
    //TODO: This NEEDS to be secure
    memset(mArr.data(), 0, size);
  }

  char* Buffer() { return mArr.data(); }
  size_t Length() { return size; }
};

Client::Impl::Impl(ClientOptions options, TCtx ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.recv)
  , mOnRecvFunc(options.onRecv)
  , mCtx(ctx)
  , mState(State::Idle)
  , mLogFunc(options.log)
  , mLogLevel(options.logLevel)
{
}

Client::Impl::~Impl()
{
}

void Client::Impl::Log(LogLevel level, const char* frmt, ...)
{
  char buffer[Impl::sMaxLogLength];
  int bytesWritten = 0;

  if (mLogLevel < level)
  {
    return;
  }

  va_list args;
  va_start(args, frmt);
  bytesWritten = vsnprintf(buffer, Impl::sMaxLogLength, frmt, args);
  va_end(args);

  //Add the null terminator.
  buffer[bytesWritten] = '\0';

  mLogFunc(buffer);
}

void Client::Impl::LogBuffer(LogLevel level, const char* pszBufferName, const char* pBuf, const int bufLen)
{
  char* pLogBuf = nullptr;
  int bytesWritten = 0;
  constexpr int extraChars = 5; //[...]\n...\n\0

  if (mLogLevel < level)
  {
    return;
  }

  const int totalBytes = (bufLen * 3) + strlen(pszBufferName) + extraChars; //Each character is actually "XX "
  pLogBuf = new char[totalBytes];
  if (pLogBuf == nullptr)
  {
    //Failed to allocate
    return;
  }

  //Output the name of the buffer we were passed
  bytesWritten = sprintf(pLogBuf, "[%s]", pszBufferName);

  //Now print each byte in hexadecimal form
  for (int i = 0; i < bufLen ; ++i)
  {
    if ((i % 16) == 0)
    {
      bytesWritten += sprintf(pLogBuf + bytesWritten, "\n ");
    }

    bytesWritten += sprintf(pLogBuf + bytesWritten, "%.2X ", pBuf[i]);
  }

  //Ensure we start a new line and end the string
  pLogBuf[bytesWritten++] = '\n';
  pLogBuf[bytesWritten++] = '\0';

  mLogFunc(pLogBuf);
}

TResult Client::Impl::Send(const char* pBuf, const int bufLen)
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
    SecureBuffer<1024> buf;
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
    LogBuffer(LogLevel::Debug, "Recv", buf.Buffer(), recievedBytes.value());
  }
}

void Client::Impl::Connect(const char* pszUser)
{
  mState = State::Connecting;

  Log(LogLevel::Info, "Beginning to connect with user %s", pszUser);

  Log(LogLevel::Debug, "Starting poll async call");
  auto fut = std::async(std::launch::async, &Impl::Poll, this);

  char buf[512];
  int bytesWritten = snprintf(buf, sizeof(buf), "SSH-2.0-billsSSH_3.6.3q3");
  buf[bytesWritten++] = CRbyte;
  buf[bytesWritten++] = LFbyte;

  Send(buf, bytesWritten);
}

void Client::Impl::Disconnect()
{
  mState = State::Disconnected;
}
