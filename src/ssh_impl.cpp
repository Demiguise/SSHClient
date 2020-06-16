#include "ssh_impl.h"
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

std::string SSH::StageToString(ConStage stage)
{
  switch (stage)
  {
    case ConStage::Null: return "Null";
    case ConStage::SentClientID: return "SentClientID";
    case ConStage::ReceivedServerID: return "ReceivedServerID";
    case ConStage::SendClientKEXInit: return "SendClientKEXInit";
    case ConStage::SentClientKEXInit: return "SentClientKEXInit";
    case ConStage::ReceivedServerKEXInit: return "ReceivedServerKEXInit";
    case ConStage::SentClientDHInit: return "SentClientDHInit";
    case ConStage::ReceivedNewKeys: return "ReceivedNewKeys";
    case ConStage::SentServiceRequest: return "SentServiceRequest";
    default: return "Unknown";
  }
}

Client::Impl::Impl(ClientOptions& options, TCtx& ctx)
  : mSendFunc(options.send)
  , mRecvFunc(options.recv)
  , mOnRecvFunc(options.onRecv)
  , mCtx(ctx)
  , mState(State::Idle)
  , mStage(ConStage::Null)
  , mLogFunc(options.log)
  , mLogLevel(options.logLevel)
  , mSequenceNumber(0)
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

void Client::Impl::SetStage(ConStage newStage)
{
  Log(LogLevel::Info, "ConStage: (%s) -> (%s)", StageToString(mStage).c_str(), StageToString(newStage).c_str());
  mStage = newStage;
}

TResult Client::Impl::Send(const Byte* pBuf, const int bufLen)
{
  auto sentBytes = mSendFunc(mCtx, pBuf, bufLen);
  if (!sentBytes.has_value())
  {
    Log(LogLevel::Warning, "Failed to send %d bytes", bufLen);
    return {};
  }

  Log(LogLevel::Debug, "Successfully sent %d/%d raw bytes", sentBytes, bufLen);
  return sentBytes;
}

TResult Client::Impl::Send(std::shared_ptr<Packet> pPacket)
{
  return pPacket->Send([&](const Byte* pBuf, const int numBytes) -> int
  {
    auto sentBytes = Send(pBuf, numBytes);
    if (!sentBytes.has_value())
    {
      return 0;
    }

    Log(LogLevel::Debug, "Packet (%d) sent %d bytes", pPacket->GetSequenceNumber(), sentBytes.value());
    return sentBytes.value();
  });
}

void Client::Impl::Queue(std::shared_ptr<Packet> pPacket)
{
  pPacket->PrepareWrite(mSequenceNumber++);
  mSendQueue.push(pPacket);
  Log(LogLevel::Debug, "Packet (%d) has been queued for sending", pPacket->GetSequenceNumber());
}

void Client::Impl::Poll()
{
  while (mState != State::Disconnected)
  {
    SecureBuffer<unsigned char, 1024> buf;

    //If we have any packets ready to send, attempt to send them now
    if (!mSendQueue.empty())
    {
      auto pPacket = mSendQueue.front();
      Send(pPacket);

      UINT32 bytesRemaining = pPacket->Remaining();
      if (bytesRemaining == 0)
      {
        Log(LogLevel::Debug, "Finished sending bytes for packet (%d)", pPacket->GetSequenceNumber());
        mSendQueue.pop();
      }
      else
      {
        Log(LogLevel::Debug, "Packet (%d) has [%d] bytes left to send", pPacket->GetSequenceNumber(), bytesRemaining);
      }
    }

    auto recievedBytes = mRecvFunc(mCtx, buf.Buffer(), buf.Length());

    if (!recievedBytes.has_value() || recievedBytes.value() == 0)
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

  if (mStage == ConStage::Null)
  {
    Log(LogLevel::Error, "Attempted to perform handshake for a NULL stage.");
    return;
  }

  /*
    Since the ServerIdent is the only stage which uses raw buffers, it is
    handled outside of the switch statement so we can process packets for every
    other stage normally.

    I feel that this is a failure of the current architecture in this setup.
  */
  if (mStage == ConStage::SentClientID)
  {
      //Now expecting that we're going to recieve the server's ID
      if (!ReceiveServerIdent(pBuf, bufLen))
      {
        Disconnect();
        return;
      }

      SetStage(ConStage::SendClientKEXInit);
      SendClientKEXInit();

      //Returning to allow for new data to populate our recv buffer
      return;
  }

  int bytesRemaining = bufLen;
  bytesRemaining -= ConsumeBuffer(pBuf, bufLen);
  while (!mRecvQueue.empty())
  {
    TPacket pPacket = mRecvQueue.front();
    if (!pPacket->Ready())
    {
      break;
    }

    pPacket->PrepareRead();

    switch (mStage)
    {
      case ConStage::SentClientKEXInit:
      {
        //Now expecting that we're going to recieve the server's KEX init
        if (!ReceiveServerKEXInit(pPacket))
        {
          Disconnect();
          return;
        }

        SetStage(ConStage::ReceivedServerKEXInit);
        [[fallthrough]];
      }
      case ConStage::ReceivedServerKEXInit:
      {
        //Now we can send our DH init
        SendClientDHInit();

        //Return here so we can process any incoming packets
        return;
      }
      case ConStage::SentClientDHInit:
      {
        //Now expecting to receive the server's DH Kex Reply
        if (!ReceiveServerDHReply(pPacket))
        {
          Disconnect();
          return;
        }

        SetStage(ConStage::ReceivedServerDHReply);
      }
      default:
      {
        Log(LogLevel::Warning, "Unhandled data for (%s) state", StateToString(mState));
        Disconnect();
        return;
      }
    }
  }
}

int Client::Impl::ParseNameList(NameList& list, const Byte* pBuf)
{
  UINT32 nameLen = swap_endian<uint32_t>(*(uint32_t*)pBuf);
  list.Init(pBuf + sizeof(UINT32), nameLen);
  return nameLen + sizeof(UINT32);
}

bool Client::Impl::ReceiveServerIdent(const Byte* pBuf, const int bufLen)
{
  std::string serverIdent;
  constexpr int minBufLen = 5;   //SSH-\LF
  constexpr int maxBufLen = 255; //RFC4253#section-4.2
  if (bufLen < minBufLen)
  {
    Log(LogLevel::Error, "Malformed ServerIdent of %d bytes. MUST be > 6", bufLen);
    return false;
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

      if (i > maxBufLen)
      {
        Log(LogLevel::Error, "Malformed ServerIdent of %d bytes. MUST be < 255", i);
        return false;
      };

      //Found the ending byte
      serverIdent.assign((char *)pBuf, i);
    }
  }

  if (serverIdent.empty())
  {
    Log(LogLevel::Info, "Unable to parse ServerIdent");
    LogBuffer(LogLevel::Debug, "ServerIdent", pBuf, bufLen);
    return false;
  }

  Log(LogLevel::Info, "ServerIdent [%d]: %s", serverIdent.length(), serverIdent.c_str());
  SetStage(ConStage::ReceivedServerID);

  return true;
}

int Client::Impl::ConsumeBuffer(const Byte* pBuf, const int bufLen)
{
  int bytesRemaining = bufLen;

  //Packets in the rear of the recvQueue get first dibs on any new data
  if (!mRecvQueue.empty())
  {
    TPacket pPacket = mRecvQueue.back();

    int bytesConsumed = pPacket->Consume(pBuf, bufLen);
    bytesRemaining -= bytesConsumed;
    Log(LogLevel::Info, "Packet (%d) consumed an additional [%d] bytes", pPacket->GetSequenceNumber(), bytesConsumed);

    UINT32 bytesNeeded = pPacket->Remaining();
    if (bytesNeeded == 0)
    {
      Log(LogLevel::Info, "Queued packet (%d) is now ready!", pPacket->GetSequenceNumber());
    }
    else
    {
      Log(LogLevel::Info, "Queued packet (%d) is waiting for [%d] more bytes", pPacket->GetSequenceNumber(), bytesNeeded);
    }
  }

  while (bytesRemaining >= 4)
  {
    auto [pNewPacket, bytesConsumed] = Packet::Create(pBuf, bufLen, mSequenceNumber);
    if (!pNewPacket)
    {
      Log(LogLevel::Error, "Failed to allocate packet (%d)!", mSequenceNumber);
      return bytesRemaining;
    }

    mSequenceNumber++;
    bytesRemaining -= bytesConsumed;

    UINT32 bytesNeeded = pNewPacket->Remaining();
    if (bytesNeeded)
    {
      //We have to wait for more data, pop this packet into the queue
      Log(LogLevel::Debug, "Queuing packet (%d) as we are waiting on [%d] bytes.", pNewPacket->GetSequenceNumber(), bytesNeeded);
      mRecvQueue.push(pNewPacket);
      break;
    }
  }

  return bufLen - bytesRemaining;
}

bool Client::Impl::ReceiveServerKEXInit(TPacket pPacket)
{
  Byte msgId;
  Byte kexCookie[cKexCookieLength];

  //Verify this is a KEX packet
  pPacket->Read(msgId);
  if (msgId != SSH_MSG::KEXINIT)
  {
    return false;
  }

  pPacket->Read(kexCookie, cKexCookieLength);
  pPacket->Read(mKex.mAlgorithms.mKex);
  pPacket->Read(mKex.mAlgorithms.mServerHost);
  pPacket->Read(mKex.mAlgorithms.mEncryption.mClientToServer);
  pPacket->Read(mKex.mAlgorithms.mEncryption.mServerToClient);
  pPacket->Read(mKex.mAlgorithms.mMAC.mClientToServer);
  pPacket->Read(mKex.mAlgorithms.mMAC.mServerToClient);
  pPacket->Read(mKex.mAlgorithms.mCompression.mClientToServer);
  pPacket->Read(mKex.mAlgorithms.mCompression.mServerToClient);
  pPacket->Read(mKex.mAlgorithms.mLanguages.mClientToServer);
  pPacket->Read(mKex.mAlgorithms.mLanguages.mServerToClient);

  //TODO: Do some processing here to pick the right algorithms to initialise

  return true;
}

void Client::Impl::SendClientKEXInit()
{
  //Now we can send the client KEXData
  KEXData clientData;

  clientData.mAlgorithms.mKex.Add("diffie-hellman-group14-sha1");

  clientData.mAlgorithms.mServerHost.Add("ssh-rsa");

  //Forcing only aes128-ctr for the moment
  clientData.mAlgorithms.mEncryption.mClientToServer.Add("aes128-ctr");
  clientData.mAlgorithms.mEncryption.mServerToClient.Add("aes128-ctr");

  //Forcing only hmac-sha2-256 for the moment
  clientData.mAlgorithms.mMAC.mClientToServer.Add("hmac-sha2-256");
  clientData.mAlgorithms.mMAC.mServerToClient.Add("hmac-sha2-256");

  //We aren't going to allow compression for the moment
  clientData.mAlgorithms.mCompression.mClientToServer.Add("none");
  clientData.mAlgorithms.mCompression.mServerToClient.Add("none");

  //Languages settings are intentionally left empty

  //Figure out the correct size of the packet
  int requiredSize = sizeof(Byte) +
                     cKexCookieLength +
                     clientData.mAlgorithms.mKex.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mServerHost.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mEncryption.mClientToServer.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mEncryption.mServerToClient.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mMAC.mClientToServer.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mMAC.mServerToClient.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mCompression.mClientToServer.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mCompression.mServerToClient.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mLanguages.mClientToServer.Len() + sizeof(UINT32) +
                     clientData.mAlgorithms.mLanguages.mServerToClient.Len() + sizeof(UINT32) +
                     sizeof(Byte) +
                     sizeof(UINT32);

  auto pClientDataPacket = Packet::Create(requiredSize);

  pClientDataPacket->Write((Byte)SSH_MSG::KEXINIT);

  Byte cookie[cKexCookieLength]; //TODO: Randomize this
  memset(cookie, 0xBE, cKexCookieLength);
  pClientDataPacket->Write(cookie, sizeof(cookie), Packet::WriteMethod::WithoutLength);

  pClientDataPacket->Write(clientData.mAlgorithms.mKex.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mServerHost.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mEncryption.mClientToServer.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mEncryption.mServerToClient.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mMAC.mClientToServer.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mMAC.mServerToClient.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mCompression.mClientToServer.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mCompression.mServerToClient.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mLanguages.mClientToServer.Str());
  pClientDataPacket->Write(clientData.mAlgorithms.mLanguages.mServerToClient.Str());

  pClientDataPacket->Write((Byte) false); //first_kex_packet_follows
  pClientDataPacket->Write(0);            //Reserved UINT32

  Queue(pClientDataPacket);

  SetStage(ConStage::SentClientKEXInit);
}

void Client::Impl::SendClientDHInit()
{
  mKEXHandler = KEX::CreateDH(DHGroups::G_14);
  auto pKEXInitPacket = mKEXHandler->CreateInitPacket();
  if (!pKEXInitPacket)
  {
    Log(LogLevel::Error, "Failed to create DH init packet");
    Disconnect();
    return;
  }

  Queue(pKEXInitPacket);

  SetStage(ConStage::SentClientDHInit);
}

bool Client::Impl::ReceiveServerDHReply(TPacket pPacket)
{
  Byte msgId;

  //Verify this is a KEX packet
  pPacket->Read(msgId);
  if (msgId != SSH_MSG::KEXDH_REPLY)
  {
    return false;
  }

  std::string keyCerts;
  MPInt f;
  std::string signature;

  pPacket->Read(keyCerts);
  pPacket->Read(f);
  pPacket->Read(signature);

  return false;
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

  Send(buf, bytesWritten);
  SetStage(ConStage::SentClientID);
}

void Client::Impl::Disconnect()
{
  Log(LogLevel::Info, "Disconnecting client");
  mState = State::Disconnected;
  SetStage(ConStage::Null);
}
