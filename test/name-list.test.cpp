#include <catch2/catch.hpp>
#include "name-list.h"
#include "packets.h"

using namespace SSH;

TEST_CASE("Namelists handle RFC Test cases", "[NameLists]")
{
  constexpr int packetLen = 128;
  PacketStore store;
  TPacket pPacket = store.Create(packetLen, PacketType::Write);

  SECTION("Empty List")
  {
    NameList empty;
    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x00
    };
    UINT32 expectedSize = 0;

    REQUIRE( empty.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(empty) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize + sizeof(UINT32)) == 0 );
  }

  SECTION("Single name")
  {
    NameList single;
    single.Add("zlib");

    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x04,
      0x7a, 0x6c, 0x69, 0x62
    };
    UINT32 expectedSize = 4;

    REQUIRE( single.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(single) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize + sizeof(UINT32)) == 0 );
  }

  SECTION("Two names")
  {
    NameList single;
    single.Add("zlib");
    single.Add("none");

    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x09,
      0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65
    };
    UINT32 expectedSize = 9;

    REQUIRE( single.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(single) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize + sizeof(UINT32)) == 0 );
  }
}
