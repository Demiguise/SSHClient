#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

enum SSH_MSG
{
  NONE                      =   0, //Not defined by RFC
  DISCONNECT                =   1,
  IGNORE                    =   2,
  UNIMPLEMENTED             =   3,
  DEBUG                     =   4,
  SERVICE_REQUEST           =   5,
  SERVICE_ACCEPT            =   6,
  KEXINIT                   =  20,
  NEWKEYS                   =  21,
  KEXDH_INIT                =  30,
  KEXDH_REPLY               =  31,
  USERAUTH_REQUEST          =  50,
  USERAUTH_FAILURE          =  51,
  USERAUTH_SUCCESS          =  52,
  USERAUTH_BANNER           =  53,
  GLOBAL_REQUEST            =  80,
  REQUEST_SUCCESS           =  81,
  REQUEST_FAILURE           =  82,
  CHANNEL_OPEN              =  90,
  CHANNEL_OPEN_CONFIRMATION =  91,
  CHANNEL_OPEN_FAILURE      =  92,
  CHANNEL_WINDOW_ADJUST     =  93,
  CHANNEL_DATA              =  94,
  CHANNEL_EXTENDED_DATA     =  95,
  CHANNEL_EOF               =  96,
  CHANNEL_CLOSE             =  97,
  CHANNEL_REQUEST           =  98,
  CHANNEL_SUCCESS           =  99,
  CHANNEL_FAILURE           = 100
};

constexpr char cKexCookieLength = 16;

#endif //~__CONSTANTS_H__
