/*
 * CitizenFX config.h for libssh
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#ifdef _MSC_VER
#define HAVE__STRTOUI64 1
#define HAVE__SNPRINTF_S 1
#define HAVE__VSNPRINTF_S 1
#define HAVE_COMPILER__FUNCTION__ 1
#define HAVE_ISBLANK 1

#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#endif
#else
#define HAVE_STRTOULL 1
#define HAVE_SNPRINTF 1
#define HAVE_VSNPRINTF 1
#endif

#define HAVE_GETADDRINFO 1

#ifdef _WIN32
#define HAVE_BOTAN 1
#endif

#define WITH_SERVER 1

#endif