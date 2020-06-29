#include "ssh_impl.h"
#include "endian.h"
#include "constants.h"
#include "crypto/crypto.h"

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
    case ConStage::ReceivedServerDHReply: return "RecievedServerDHReply";
    case ConStage::ReceivedNewKeys: return "ReceivedNewKeys";
    case ConStage::SentNewKeys: return "SentNewKeys";
    case ConStage::SentServiceRequest: return "SentServiceRequest";
    case ConStage::ReceivedServiceAccept: return "RecievedServiceAccept";
    case ConStage::AttemptingUserAuth: return "AttemptingUserAuth";
    case ConStage::UserLoggedIn: return "UserLoggedIn";
    default: return "Unknown";
  }
}

std::string SSH::AuthMethodToString(UserAuthMethod method)
{
  switch (method)
  {
    case UserAuthMethod::None: return "none";
    case UserAuthMethod::Password: return "password";
    default: return "unknown";
  }
}

Client::Impl::Impl(ClientOptions& options, TCtx& ctx, Client* pOwner)
  : mOpts(options)
  , mActiveAuthMethod(UserAuthMethod::None)
  , mCtx(ctx)
  , mState(State::Idle)
  , mStage(ConStage::Null)
  , mpOwner(pOwner)
  , mIncomingSequenceNumber(0)
  , mOutgoingSequenceNumber(0)
{
  mClientKex.mIdent = "SSH-2.0-cppsshSSH_3.6.3q3";

  mClientKex.mAlgorithms.mKex.Add("diffie-hellman-group14-sha1");

  mClientKex.mAlgorithms.mServerHost.Add("ssh-rsa");

  //Forcing only aes128-ctr for the moment
  Crypto::PopulateNamelist(mClientKex.mAlgorithms.mEncryption.mClientToServer);
  Crypto::PopulateNamelist(mClientKex.mAlgorithms.mEncryption.mServerToClient);

  //Forcing only hmac-sha2-256 for the moment
  mClientKex.mAlgorithms.mMAC.mClientToServer.Add("hmac-sha2-256");
  mClientKex.mAlgorithms.mMAC.mServerToClient.Add("hmac-sha2-256");

  //We aren't going to allow compression for the moment
  mClientKex.mAlgorithms.mCompression.mClientToServer.Add("none");
  mClientKex.mAlgorithms.mCompression.mServerToClient.Add("none");

  //Languages settings are intentionally left empty
}

Client::Impl::~Impl()
{
}

void Client::Impl::Log(LogLevel level, const std::string frmt, ...)
{
  char buffer[Impl::sMaxLogLength];
  int bytesWritten = 0;

  if (mOpts.mLogLevel < level)
  {
    return;
  }

  va_list args;
  va_start(args, frmt);
  bytesWritten = vsnprintf(buffer, Impl::sMaxLogLength, frmt.c_str(), args);
  va_end(args);

  //Add the null terminator.
  buffer[bytesWritten] = '\0';

  mOpts.mLogFunc(buffer);
}

void Client::Impl::LogBuffer(LogLevel level, const std::string bufferName, const Byte* pBuf, const int bufLen)
{
  std::unique_ptr<char[]> pLogBuf;
  int bytesWritten = 0;
  constexpr int extraChars = 4; //[...]\n...\0
  constexpr int columnLimit = 16;

  if (mOpts.mLogLevel < level)
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

  mOpts.mLogFunc(pLogBuf.get());
}

void Client::Impl::SetStage(ConStage newStage)
{
  Log(LogLevel::Info, "ConStage: (%s) -> (%s)", StageToString(mStage).c_str(), StageToString(newStage).c_str());
  mStage = newStage;
}

void Client::Impl::SetState(State newState)
{
  Log(LogLevel::Info, "State: (%s) -> (%s)", StateToString(mState), StateToString(newState));
  mState = newState;
}

TResult Client::Impl::Raw_Send(const Byte* pBuf, const int bufLen)
{
  auto sentBytes = mOpts.mSend(mCtx, pBuf, bufLen);
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
    auto sentBytes = Raw_Send(pBuf, numBytes);
    if (!sentBytes.has_value())
    {
      return 0;
    }

    if (sentBytes.value() == -1)
    {
      //User's send function has signalled a failure to send, simply disconnect to stop all further traffic.
      Disconnect();
      return 0;
    }

    Log(LogLevel::Debug, "Packet (%d) sent %d bytes", pPacket->GetSequenceNumber(), sentBytes.value());
    return sentBytes.value();
  });
}

TResult Client::Impl::Send(TChannelID channelID, const Byte* pBuf, const int bufLen)
{
  TChannel channel = GetChannel(channelID);
  if (channel == nullptr)
  {
    return {};
  }

  TPacket dataPacket = channel->PrepareSend(pBuf, bufLen, mPacketStore);
  if (dataPacket == nullptr)
  {
    return false;
  }

  Queue(dataPacket);
  return dataPacket->PayloadLen();
}

void Client::Impl::Queue(std::shared_ptr<Packet> pPacket)
{
  pPacket->PrepareWrite(mOutgoingSequenceNumber++);
  mSendQueue.push(pPacket);
  Log(LogLevel::Debug, "Packet (%d) has been queued for sending", pPacket->GetSequenceNumber());
}

void Client::Impl::Poll()
{
  while (mState != State::Disconnected)
  {
    SecureBuffer<unsigned char, 1024> buf;

    //If we have any packets ready to send, attempt to send them now
    while (!mSendQueue.empty())
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
        break;
      }
    }

    auto recievedBytes = mOpts.mRecv(mCtx, buf.Buffer(), buf.Length());

    if (!recievedBytes.has_value() || recievedBytes.value() == 0)
    {
      //No data received, nothing to do.
      continue;
    }

    if (recievedBytes.value() == -1)
    {
      //User's recv function has signalled a failure to recv, simply disconnect to stop all further traffic.
      Disconnect();
      return;
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
  int bytesConsumed = ConsumeBuffer(pBuf, bufLen);
  if (bytesConsumed < 0)
  {
    Disconnect();
    return;
  }

  bytesRemaining -= bytesConsumed;
  while (!mRecvQueue.empty())
  {
    TPacket pPacket = mRecvQueue.front();
    if (!pPacket->Ready())
    {
      break;
    }

    mRecvQueue.pop();

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

        break; //Allow for more packets to be handled
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
        break; //Allow for more packets to be handled
      }
      case ConStage::ReceivedServerDHReply:
      {
        //Now expecting to recieve a NewKeys message
        if (!ReceiveNewKeys(pPacket))
        {
          Disconnect();
          return;
        }

        SetStage(ConStage::ReceivedNewKeys);
        [[fallthrough]];
      }
      case ConStage::ReceivedNewKeys:
      {
        //Send our new keys message
        SendNewKeys();
        SetStage(ConStage::SentNewKeys);
        [[fallthrough]];
      }
      case ConStage::SentNewKeys:
      {
        //Send the service request
        SendServiceRequest();
        SetStage(ConStage::SentServiceRequest);
        break;
      }
      case ConStage::SentServiceRequest:
      {
        //Now expecting to receive a Service_Accept
        if (!ReceiveServiceAccept(pPacket))
        {
          Disconnect();
          return;
        }

        SetStage(ConStage::ReceivedServiceAccept);
        SetState(State::Authenticating);

        /*
          Clients can send a "none" authentication method message
          to get information on which authentication methods the server
          will accept.
        */
        SendUserAuthRequest(UserAuthMethod::None);

        SetStage(ConStage::AttemptingUserAuth);
        break;
      }
      case ConStage::AttemptingUserAuth:
      {
        UserAuthResponse response = ReceiveUserAuth(pPacket);
        switch (response)
        {
          case UserAuthResponse::Success:
          {
            SetStage(ConStage::UserLoggedIn);
            SetState(State::Connected);

            mOpts.mOnConnect(mpOwner);

            break;
          }
          case UserAuthResponse::Banner:
          {
            //Do nothing
            break;
          }
          case UserAuthResponse::Retry:
          {
            if (mOpts.mAuthMethods.size() != 0)
            {
              UserAuthMethod newMethod = mOpts.mAuthMethods.front();
              mOpts.mAuthMethods.pop();

              SendUserAuthRequest(newMethod);

              break;
            }
            else
            {
              Log(LogLevel::Info, "No more available authentication methods");
              Disconnect();
              return;
            }
          }
          case UserAuthResponse::Failure:
          default:
          {
            Disconnect();
            return;
          }
        }

        break;
      }
      case ConStage::UserLoggedIn:
      {
        if (!ReceiveMessage(pPacket))
        {
          Disconnect();
          return;
        }
        break;
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
      std::string ident;
      if (pBuf[i - 1] != CRbyte)
      {
        Log(LogLevel::Warning, "ServerIdent did not use RFC standard <CR><LR> ending.");
        ident.assign((char *)pBuf, i);
      }
      else
      {
        ident.assign((char *)pBuf, i-1);
      }

      if (i > maxBufLen)
      {
        Log(LogLevel::Error, "Malformed ServerIdent of %d bytes. MUST be < 255", i);
        return false;
      };

      //Found the ending byte
      serverIdent = ident;
      break;
    }
  }

  if (serverIdent.empty())
  {
    Log(LogLevel::Info, "Unable to parse ServerIdent");
    LogBuffer(LogLevel::Debug, "ServerIdent", pBuf, bufLen);
    return false;
  }

  Log(LogLevel::Info, "ServerIdent [%d]: %s", serverIdent.length(), serverIdent.c_str());
  mServerKex.mIdent = serverIdent;

  SetStage(ConStage::ReceivedServerID);

  return true;
}

int Client::Impl::ConsumeBuffer(const Byte* pBuf, const int bufLen)
{
  int bytesRemaining = bufLen;
  const Byte* pIter = pBuf;

  //Packets in the rear of the recvQueue get first dibs on any new data
  if (!mRecvQueue.empty())
  {
    TPacket pPacket = mRecvQueue.back();

    int bytesConsumed = pPacket->Consume(pIter, bufLen);
    bytesRemaining -= bytesConsumed;
    pIter += bytesConsumed;
    Log(LogLevel::Info, "Packet (%d) consumed an additional [%d] bytes", pPacket->GetSequenceNumber(), bytesConsumed);

    UINT32 bytesNeeded = pPacket->Remaining();
    if (bytesNeeded == 0)
    {
      Log(LogLevel::Info, "Queued packet (%d) [Payload: %u] is now ready!", pPacket->GetSequenceNumber(), pPacket->PayloadLen());

      if (!pPacket->PrepareRead())
      {
        Log(LogLevel::Error, "Failed to prepare to read");
        return -1;
      }
    }
    else
    {
      Log(LogLevel::Info, "Queued packet (%d) is waiting for [%d] more bytes", pPacket->GetSequenceNumber(), bytesNeeded);
    }
  }

  while (bytesRemaining >= 4)
  {
    auto [pNewPacket, bytesConsumed] = mPacketStore.Create(pIter, bytesRemaining, mIncomingSequenceNumber, PacketType::Read);
    if (!pNewPacket)
    {
      Log(LogLevel::Error, "Failed to allocate incoming packet (%d)!", mIncomingSequenceNumber);
      return bytesRemaining;
    }

    mIncomingSequenceNumber++;
    bytesRemaining -= bytesConsumed;
    pIter += bytesConsumed;

    mRecvQueue.push(pNewPacket);

    UINT32 bytesNeeded = pNewPacket->Remaining();
    if (bytesNeeded)
    {
      //We have to wait for more data, pop this packet into the queue
      Log(LogLevel::Debug, "Packet (%d) is waiting on [%d] bytes.", pNewPacket->GetSequenceNumber(), bytesNeeded);
      break;
    }

    if (!pNewPacket->PrepareRead())
    {
      Log(LogLevel::Error, "Failed to prepare to read");
      return -1;
    }

    Log(LogLevel::Info, "Packet (%d) [Payload: %u] now ready", pNewPacket->GetSequenceNumber(), pNewPacket->PayloadLen());
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
  pPacket->Read(mServerKex.mAlgorithms.mKex);
  pPacket->Read(mServerKex.mAlgorithms.mServerHost);
  pPacket->Read(mServerKex.mAlgorithms.mEncryption.mClientToServer);
  pPacket->Read(mServerKex.mAlgorithms.mEncryption.mServerToClient);
  pPacket->Read(mServerKex.mAlgorithms.mMAC.mClientToServer);
  pPacket->Read(mServerKex.mAlgorithms.mMAC.mServerToClient);
  pPacket->Read(mServerKex.mAlgorithms.mCompression.mClientToServer);
  pPacket->Read(mServerKex.mAlgorithms.mCompression.mServerToClient);
  pPacket->Read(mServerKex.mAlgorithms.mLanguages.mClientToServer);
  pPacket->Read(mServerKex.mAlgorithms.mLanguages.mServerToClient);

  //TODO: Do some processing here to pick the right algorithms to initialise or whether to disconnect


  mServerKex.mKEXInit = mPacketStore.Copy(pPacket);

  return true;
}

void Client::Impl::SendClientKEXInit()
{
  //Figure out the correct size of the packet
  int requiredSize = sizeof(Byte) +
                     cKexCookieLength +
                     mClientKex.mAlgorithms.mKex.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mServerHost.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mEncryption.mClientToServer.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mEncryption.mServerToClient.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mMAC.mClientToServer.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mMAC.mServerToClient.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mCompression.mClientToServer.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mCompression.mServerToClient.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mLanguages.mClientToServer.Len() + sizeof(UINT32) +
                     mClientKex.mAlgorithms.mLanguages.mServerToClient.Len() + sizeof(UINT32) +
                     sizeof(Byte) +
                     sizeof(UINT32);

  auto pClientDataPacket = mPacketStore.Create(requiredSize, PacketType::Write);

  pClientDataPacket->Write(SSH_MSG::KEXINIT);

  Byte cookie[cKexCookieLength]; //TODO: Randomize this
  memset(cookie, 0xBE, cKexCookieLength);
  pClientDataPacket->Write(cookie, sizeof(cookie), Packet::WriteMethod::WithoutLength);

  pClientDataPacket->Write(mClientKex.mAlgorithms.mKex.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mServerHost.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mEncryption.mClientToServer.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mEncryption.mServerToClient.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mMAC.mClientToServer.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mMAC.mServerToClient.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mCompression.mClientToServer.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mCompression.mServerToClient.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mLanguages.mClientToServer.Str());
  pClientDataPacket->Write(mClientKex.mAlgorithms.mLanguages.mServerToClient.Str());

  pClientDataPacket->Write((Byte) false); //first_kex_packet_follows
  pClientDataPacket->Write(0);            //Reserved UINT32

  Queue(pClientDataPacket);

  mClientKex.mKEXInit = mPacketStore.Copy(pClientDataPacket);

  SetStage(ConStage::SentClientKEXInit);
}

void Client::Impl::SendClientDHInit()
{
  mKEXHandler = KEX::CreateDH(DHGroups::G_14);
  auto pKEXInitPacket = mKEXHandler->CreateInitPacket(mPacketStore);
  if (!pKEXInitPacket)
  {
    Log(LogLevel::Error, "Failed to create DH init packet");
    Disconnect();
    return;
  }

  Queue(pKEXInitPacket);

  SetStage(ConStage::SentClientDHInit);

  //Set keys now that we have a DH Init in progress
  UINT32 blockLen = mKEXHandler->GetBlockSize();
  UINT32 keyLen = mKEXHandler->GetKeySize();
  UINT32 macLen = MAC::Len(MACHandlers::HMAC_SHA2_256);
  mRemoteKeys.mIV.SetLen(blockLen);
  mRemoteKeys.mEnc.SetLen(keyLen);
  mRemoteKeys.mMac.SetLen(macLen);

  mLocalKeys.mIV.SetLen(blockLen);
  mLocalKeys.mEnc.SetLen(keyLen);
  mLocalKeys.mMac.SetLen(macLen);
}

bool Client::Impl::ReceiveServerDHReply(TPacket pPacket)
{
  if (!mKEXHandler->VerifyReply(mServerKex, mClientKex, pPacket))
  {
    Log(LogLevel::Error, "Failed to verify ServerDHReply");
    Disconnect();
    return false;
  }

  Log(LogLevel::Info, "Verified ServerDHReply");

  //If we don't already have a session ID, grab it from the KEX handler
  if (mSessionID.Len() == 0)
  {
    mSessionID = mKEXHandler->GetSessionID();
  }

  bool bSuccess = false;
  //Generate RemoteKeys
  bSuccess = mKEXHandler->GenerateKey(mRemoteKeys.mIV, mSessionID, 'B');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Remote IV key");
    return false;
  }

  bSuccess = mKEXHandler->GenerateKey(mRemoteKeys.mEnc, mSessionID, 'D');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Remote encryption key");
    return false;
  }

  bSuccess = mKEXHandler->GenerateKey(mRemoteKeys.mMac, mSessionID, 'F');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Remote MAC key");
    return false;
  }

  //Generate LocalKeys
  bSuccess = mKEXHandler->GenerateKey(mLocalKeys.mIV, mSessionID, 'A');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Local IV key");
    return false;
  }

  bSuccess = mKEXHandler->GenerateKey(mLocalKeys.mEnc, mSessionID, 'C');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Local encryption key");
    return false;
  }

  bSuccess = mKEXHandler->GenerateKey(mLocalKeys.mMac, mSessionID, 'E');
  if (!bSuccess)
  {
    Log(LogLevel::Error, "Failed to generate Local MAC key");
    return false;
  }

  return true;
}

bool Client::Impl::ReceiveNewKeys(TPacket pPacket)
{
  Byte msgId;

  //Verify this is a NewKeys packet
  pPacket->Read(msgId);
  if (msgId != SSH_MSG::NEWKEYS)
  {
    Log(LogLevel::Error, "Expected NEWKEYS message ID but got %u instead", msgId);
    return false;
  }

  Log(LogLevel::Info, "Received NewKeys message");

  //We can now activate MAC integrity for incoming packets
  TMACHandler macHandler = MAC::Create(MACHandlers::HMAC_SHA2_256);
  if (!macHandler->SetKey(mRemoteKeys.mMac))
  {
    Log(LogLevel::Error, "Unable to set keys for MAC Handler");
    return false;
  }

  //We can now activate decryption for incoming packets
  TCryptoHandler cryptoHandler = Crypto::Create(CryptoHandlers::AES128_CTR);
  if (!cryptoHandler->SetKey(mRemoteKeys.mEnc, mRemoteKeys.mIV))
  {
    Log(LogLevel::Error, "Unable to set keys for Decryption Handler");
    return false;
  }

  mPacketStore.SetIncomingMACHandler(macHandler);
  mPacketStore.SetDecryptionHandler(cryptoHandler);
  Log(LogLevel::Info, "Set new Incoming MAC and Decryption Handlers");

  return true;
}

void Client::Impl::SendNewKeys()
{
  TPacket pPacket = mPacketStore.Create(1, PacketType::Write);
  pPacket->Write(SSH_MSG::NEWKEYS);

  //We can now activate MAC integrity for outgoing packets
  TMACHandler macHandler = MAC::Create(MACHandlers::HMAC_SHA2_256);
  if (!macHandler->SetKey(mLocalKeys.mMac))
  {
    Log(LogLevel::Error, "Unable to set keys for MAC Handler");
    return;
  }

  //We can now activate encryption for outgoing packets
  TCryptoHandler cryptoHandler = Crypto::Create(CryptoHandlers::AES128_CTR);
  if (!cryptoHandler->SetKey(mLocalKeys.mEnc, mLocalKeys.mIV))
  {
    Log(LogLevel::Error, "Unable to set keys for Encryption Handler");
    return;
  }

  mPacketStore.SetOutgoingMACHandler(macHandler);
  mPacketStore.SetEncryptionHandler(cryptoHandler);
  Log(LogLevel::Info, "Set new Outgoing MAC and Encryption Handlers");

  Queue(pPacket);
}

void Client::Impl::SendServiceRequest()
{
  std::string userAuth = "ssh-userauth";
  UINT32 packetLen = sizeof(Byte) +     //SSH_MSG
                     sizeof(UINT32) +   //Length of string
                     userAuth.length(); //String

  TPacket pPacket = mPacketStore.Create(packetLen, PacketType::Write);

  pPacket->Write(SSH_MSG::SERVICE_REQUEST);
  pPacket->Write(userAuth);

  Queue(pPacket);
}

bool Client::Impl::ReceiveServiceAccept(TPacket pPacket)
{
  Byte msgId;

  //Verify this is the packet type we are expecting
  pPacket->Read(msgId);
  if (msgId != SSH_MSG::SERVICE_ACCEPT)
  {
    Log(LogLevel::Error, "Expected Service Accept message ID but got %u instead", msgId);
    return false;
  }

  Log(LogLevel::Info, "Received service accept");
  return true;
}

void Client::Impl::SendUserAuthRequest(UserAuthMethod method)
{
  //Service name here refers to the service to start AFTER userauth has succeeded
  std::string serviceName = "ssh-connection";
  std::string methodName = AuthMethodToString(method);
  TPacket pPacket = nullptr;

  //This packet length changes depending on what methods are used
  UINT32 packetLen =  sizeof(Byte) +          //SSH_MSG
                      sizeof(UINT32) +        //User name length field
                      mOpts.mUserName.length() +    //User name
                      sizeof(UINT32) +        //Service name length field
                      serviceName.length() +  //Service name
                      sizeof(UINT32) +        //Method name length field
                      methodName.length();    //Method name

  Log(LogLevel::Info, "Attempting to login via %s method", methodName.c_str());

  switch (method)
  {
    case UserAuthMethod::Password:
    {
      //Get user's password from our authentication function
      SecureBuffer<Byte, 512> passwordBuffer;
      auto passwordLen = mOpts.mOnAuth(mCtx, method, passwordBuffer.Buffer(), passwordBuffer.Length());

      if (!passwordLen.has_value())
      {
        Disconnect();
        return;
      }

      packetLen +=  sizeof(Byte) +        //Password change request ("Usually false")
                    sizeof(UINT32) +      //Password field length
                    passwordLen.value();  //Password

      pPacket = mPacketStore.Create(packetLen, PacketType::Write);

      pPacket->Write(SSH_MSG::USERAUTH_REQUEST);
      pPacket->Write(mOpts.mUserName);
      pPacket->Write(serviceName);
      pPacket->Write(methodName);
      pPacket->Write(false);  //This is not a password change request
      pPacket->Write(passwordBuffer.Buffer(), passwordLen.value());

      break;
    }
    case UserAuthMethod::None:
    {
      //None is special and requires no other data
      pPacket = mPacketStore.Create(packetLen, PacketType::Write);

      pPacket->Write(SSH_MSG::USERAUTH_REQUEST);
      pPacket->Write(mOpts.mUserName);
      pPacket->Write(serviceName);
      pPacket->Write(methodName);

      break;
    }
    default:
    {
      //We've clearly added a new authentication method with no handling
      Disconnect();
      return;
    }
  }

  Queue(pPacket);
  mActiveAuthMethod = method;
}

Client::Impl::UserAuthResponse Client::Impl::ReceiveUserAuth(TPacket pPacket)
{
  Byte msgId;

  //Verify this is a NewKeys packet
  pPacket->Read(msgId);

  switch (msgId)
  {
    case SSH_MSG::USERAUTH_BANNER:
    {
      //We don't do anything with the banner messages at the moment but we can log them out regardless.
      std::string bannerMessage;
      pPacket->Read(bannerMessage);
      Log(LogLevel::Info, "Banner Message: %s", bannerMessage.c_str());
      return UserAuthResponse::Banner;
    }
    case SSH_MSG::USERAUTH_FAILURE:
    {
      NameList availableMethods;
      Byte bPartialSuccess = 0;
      pPacket->Read(availableMethods);
      pPacket->Read(bPartialSuccess);

      Log(LogLevel::Info, "Userauth Failure. Remaining methods [%s]", availableMethods.Str().c_str());
      //TODO: Actually care about the methods the server sends us

      if (availableMethods.Len() == 0)
      {
        return UserAuthResponse::Failure;
      }
      else
      {
        return UserAuthResponse::Retry;
      }
    }
    case SSH_MSG::USERAUTH_SUCCESS:
    {
      //Nothing else to do
      return UserAuthResponse::Success;
    }
    default:
    {
      Log(LogLevel::Error, "Unhandled message ID during user auth (%u)", msgId);
      return UserAuthResponse::Failure;
    }
  }
}

TChannel Client::Impl::GetChannel(TChannelID id)
{
  auto iter = std::find_if(mChannels.begin(), mChannels.end(), [&](TChannel channel)
  {
    return (channel->ID() == id);
  });

  return (iter == mChannels.end()) ? nullptr : *iter;
}

TChannelID Client::Impl::OpenChannel(ChannelTypes type, TOnEventFunc callback)
{
  TChannel newChannel = Channel::Create(type, mNextChannelID++, callback);
  if (newChannel == nullptr)
  {
    return 0;
  }

  TPacket openPacket = newChannel->CreateOpenPacket(mPacketStore);
  if (openPacket == nullptr)
  {
    CloseChannel(newChannel->ID());
    return 0;
  }

  Queue(openPacket);

  return newChannel->ID();
}

bool Client::Impl::CloseChannel(TChannelID channelID)
{
  TChannel oldChannel = GetChannel(channelID);
  if (oldChannel == nullptr)
  {
    return false;
  }

  if (oldChannel->State() == ChannelState::Open)
  {
    TPacket closePacket = oldChannel->CreateClosePacket(mPacketStore);
    if (closePacket == nullptr)
    {
      return false;
    }

    Queue(closePacket);
  }

  return true;
}

bool Client::Impl::ReceiveMessage(TPacket pPacket)
{
  Byte msgId;

  pPacket->Peek(msgId);

  switch (msgId)
  {
    case SSH_MSG::CHANNEL_OPEN_CONFIRMATION:
    case SSH_MSG::CHANNEL_DATA:
    {
      TChannelID recipientChannelID = 0;
      pPacket->Read(msgId);
      pPacket->Read(recipientChannelID);

      TChannel channel = GetChannel(recipientChannelID);
      if (channel == nullptr)
      {
        return false;
      }

      channel->HandleData(msgId, pPacket);

      break;
    }
    default: break;
  }

  return true;
}

void Client::Impl::Connect()
{
  Log(LogLevel::Info, "Beginning to connect with user %s", mOpts.mUserName.c_str());

  Byte buf[512];
  int bytesWritten = snprintf((char*)buf, sizeof(buf), "%s", mClientKex.mIdent.c_str());
  buf[bytesWritten++] = CRbyte;
  buf[bytesWritten++] = LFbyte;

  Raw_Send(buf, bytesWritten);
  SetStage(ConStage::SentClientID);

  SetState(State::Connecting);

  Log(LogLevel::Debug, "Starting poll async call");
  auto fut = std::async(std::launch::async, &Impl::Poll, this);
}

void Client::Impl::Disconnect()
{
  Log(LogLevel::Info, "Disconnecting client");
  SetState(State::Disconnected);
  SetStage(ConStage::Null);
}

