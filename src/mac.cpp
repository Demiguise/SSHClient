#include "mac.h"

using namespace SSH;

void MAC::PopulateNamelist(NameList& list)
{
  list.Add("hmac-sha2-256");
}

class NoneHandler : public IMACHandler
{
public:
  NoneHandler() = default;

  virtual UINT32 Len() override
  {
    return 0;
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

TMACHandler MAC::Create(MACHandlers handler)
{
  switch (handler)
  {
    default:
    case MACHandlers::None:
      return std::make_shared<NoneHandler>();
  }
}
