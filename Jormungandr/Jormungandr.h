#ifndef JORMUNGANDR_H
#define JORMUNGANDR_H

#include "pch.h"

#include "WindowsTypes.hpp"
#include "JormungandrCommon.hpp"
#include "JormungandrHelper.hpp"
#include "COFFLdr.hpp"

constexpr UNICODE_STRING DRIVER_NAME = RTL_CONSTANT_STRING(L"\\Driver\\Jormungandr");
constexpr UNICODE_STRING DRIVER_DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\Jormungandr");
constexpr UNICODE_STRING DRIVER_SYMBOLIC_LINK = RTL_CONSTANT_STRING(L"\\??\\Jormungandr");

DRIVER_UNLOAD JormungandrUnload;
DRIVER_DISPATCH JormungandrCreateClose, JormungandrWrite;

#endif