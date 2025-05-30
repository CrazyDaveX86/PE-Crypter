#pragma once

#include "main.hpp"
#include "loader_stub_config.hpp"

#ifndef PE_MODIFIER_H
#define PE_MODIFIER_H

DWORD Align(DWORD value, DWORD alignment);
BYTE* AddLoaderSectionToPE(BYTE* pOriginalPayloadBuffer, DWORD* pPayloadFileSize, const LoaderMetadata* pLoaderData, DWORD* outLoaderRva);

#endif