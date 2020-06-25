#include "mac.h"

using namespace SSH;

void MAC::PopulateNamelist(NameList& list)
{
  list.Add("hmac-sha2-256");
}

class None_MACHandler : public IMACHandler
{
public:
  None_MACHandler() = default;

  virtual UINT32 Len() override
  {
    return 0;
  }

  virtual bool SetKey(const Key& macKey, const Key& ivKey) override
  {
    return true;
  }

  virtual bool Create(TPacket pPacket) override
  {
    return true;
  }

  virtual bool Verify(TPacket pPacket) override
  {
    return true;
  }

  virtual MACHandlers Type() override { return MACHandlers::None; }
};

class HMAC_SHA2_256_MACHandler : public IMACHandler
{
public:
  HMAC_SHA2_256_MACHandler() = default;

  virtual UINT32 Len() override
  {
    return 0;
  }

  virtual bool SetKey(const Key& macKey, const Key& ivKey) override
  {
    return true;
  }

  virtual bool Create(TPacket pPacket) override
  {
    return true;
  }

  virtual bool Verify(TPacket pPacket) override
  {
    return true;
  }

  virtual MACHandlers Type() override { return MACHandlers::HMAC_SHA2_256; }
};

TMACHandler MAC::Create(MACHandlers handler)
{
  switch (handler)
  {
    case MACHandlers::HMAC_SHA2_256:
      return std::make_shared<HMAC_SHA2_256_MACHandler>();
    default:
    case MACHandlers::None:
      return std::make_shared<None_MACHandler>();
  }
}
