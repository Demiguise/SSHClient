#include <catch2/catch.hpp>
#include "mpint.h"
#include "packets.h"
#include "endian.h"

using namespace SSH;

TEST_CASE("MPInts handle RFC Test cases", "[MPInt]")
{
  MPInt testInt;
  constexpr int packetLen = 128;
  TPacket pPacket = Packet::Create(packetLen);

  SECTION("Zero sized MPInt")
  {
    testInt.Init(nullptr, 0);
    testInt.Pad();

    REQUIRE( testInt.Len() == 0 );

    //Make sure the packet only wrote a single 4 byte UINT32 field
    REQUIRE( pPacket->Write(testInt) == 4 );

    UINT32* pSize = (UINT32*)pPacket->Payload();
    REQUIRE ( *pSize == 0 );
  }

  SECTION("8 Byte MPint")
  {
    Byte testData[] = {
      0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7
    };
    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x08,
      0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7
    };
    UINT32 expectedSize = 8;

    testInt.Init(testData, sizeof(testData));
    testInt.Pad();

    REQUIRE( testInt.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(testInt) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize) == 0 );
  }

  SECTION("Padded MPint")
  {
    Byte testData[] = {
      0x80
    };
    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x80
    };
    UINT32 expectedSize = 2;

    testInt.Init(testData, sizeof(testData));
    testInt.Pad();

    REQUIRE( testInt.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(testInt) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize) == 0 );
  }

  SECTION("Short negative MPint")
  {
    Byte testData[] = {
      0xed, 0xcc
    };
    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x02,
      0xed, 0xcc
    };
    UINT32 expectedSize = 2;

    testInt.Init(testData, sizeof(testData));
    testInt.Pad();

    REQUIRE( testInt.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(testInt) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize) == 0 );
  }

  SECTION("Long negative MPint")
  {
    Byte testData[] = {
      0xff, 0x21, 0x52, 0x41, 0x11
    };
    Byte expectedOut[] = {
      0x00, 0x00, 0x00, 0x05,
      0xff, 0x21, 0x52, 0x41, 0x11
    };
    UINT32 expectedSize = 5;

    testInt.Init(testData, sizeof(testData));
    testInt.Pad();

    REQUIRE( testInt.Len() == expectedSize );

    //Make sure the packet wrote the whole field
    REQUIRE( pPacket->Write(testInt) == expectedSize + sizeof(UINT32) );

    REQUIRE ( memcmp(expectedOut, pPacket->Payload(), expectedSize) == 0 );
  }
}
