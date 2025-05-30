# PE File Crypter and Loader
This project implements a crypter for Portable Executable (PE) files. Its primary function is to encrypt specified sections of an input PE file and prepend a loader stub. This loader is responsible for decrypting these sections in memory at runtime before transferring execution to the original entry point of the application.

## Core Functionality
*   **PE File Analysis**: Performs an initial analysis of the input PE file, extracting and logging information such as architecture, entry point, section details, and import table data.
*   **Selective Section Encryption**: Employs XOR encryption for the `.text`, `.data`, and `.rdata` sections of the PE file.
*   **Loader Stub Injection**: A custom loader, implemented as shellcode, is injected into a new section (default name: `.lol`) within the PE file. This section is marked as executable.
*   **PE Header Modification**: The PE file's NT Headers are modified to accommodate the new loader section. This includes updating the number of sections, `SizeOfHeaders`, `SizeOfImage`, and redirecting the `AddressOfEntryPoint` to the loader stub.
*   **Configuration-Driven Loader**: The loader stub utilizes a `LoaderMetadata` structure, appended after the shellcode, which contains the original entry point RVA, decryption key, and RVAs/sizes of the encrypted sections.
*   **Diagnostic Logging**: Outputs detailed operational information and diagnostic messages to a specified log file.

## Operational Workflow
The crypter operates through the following stages:
1.  **Analysis Phase (`analyzer.cpp`)**: The input PE file is parsed to extract and log header information, section table details, and import directory data.
2.  **Encryption Phase (`encrypter.cpp`)**:
    *   The input PE file is read into memory.
    *   The `.text`, `.data`, and `.rdata` sections are encrypted in-place using an XOR operation with a predefined key.
    *   This modified buffer is retained in memory for further processing; an intermediate encrypted file is also written to disk.
3.  **Metadata Preparation (`main.cpp`)**:
    *   Essential metadata for the loader is compiled: the Original Entry Point (OEP) RVA, the encryption key, and the RVA and virtual size of each encrypted section. This data populates the `LoaderMetadata` structure.
4.  **PE Modification Phase (`pe_modifier.cpp`)**:
    *   The in-memory PE buffer (containing the encrypted sections) is further modified.
    *   Space is made in the PE header for a new section header entry. If necessary, this may involve increasing `SizeOfHeaders` and potentially shifting the raw data offsets of existing sections.
    *   A new section header is created for the loader.
    *   The loader shellcode (from `loader_stub_config.cpp`) and the `LoaderMetadata` structure are written into this new section. The section is marked as readable and executable.
    *   The PE's NT Headers are updated: `FileHeader.NumberOfSections` is incremented, `OptionalHeader.SizeOfHeaders` is adjusted if necessary, `OptionalHeader.SizeOfImage` is recalculated to include the new section, and `OptionalHeader.AddressOfEntryPoint` is set to the RVA of the loader stub.
5.  **Output Generation**: The final modified PE buffer, now containing the encrypted original code and the loader stub, is written to the specified output file.

**Runtime Behavior (Loader Stub):**
1.  Upon execution of the packed PE, the operating system transfers control to the loader stub within the `.lol` section.
2.  The loader stub performs self-location and retrieves the `LoaderMetadata`.
3.  It dynamically resolves necessary Windows API functions (e.g., `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`).
4.  For each encrypted section (as defined in `LoaderMetadata`):
    *   The memory region of the section is made writable using `VirtualProtect`.
    *   The section data is decrypted in memory using the XOR key.
    *   The memory protection is restored to its original (or appropriate executable/read-only) state using `VirtualProtect`.
5.  Execution is transferred to the Original Entry Point (OEP) of the application.

## Module Descriptions
*   **`main.cpp`**: Orchestrates the overall crypting process, coordinating other modules.
*   **`analyzer.cpp / .hpp`**: Responsible for parsing and displaying PE file structure information.
*   **`encrypter.cpp / .hpp`**: Handles the XOR encryption of designated PE sections.
*   **`pe_modifier.cpp / .hpp`**: Implements the logic for adding the loader section and modifying PE headers.
*   **`loader_stub_config.cpp / .hpp`**: Contains the pre-compiled x64 loader shellcode and the `LoaderMetadata` structure definition.
*   **`common.cpp / .hpp`**: Provides common utility functions for PE manipulation, such as RVA to raw offset conversion.
*   **`main.hpp`**: Contains common includes and the `logf` logging macro.

## Usage
**Example:**
   ```./crypter.exe C:\path\to\original.exe C:\path\to\encrypted.bin C:\path\to\packed.exe C:\path\to\crypter_debug.log```

**Arguments:**
-    <input_pe_file>: Path to the target PE file to be processed.
-    <output_encrypted_intermediate_file>: Path for the intermediate file where the PE with encrypted sections (prior to loader addition) will be saved.
-    <output_final_packed_file>: Path for the final packed PE file containing the loader and encrypted payload.
-    <log_filename>: Path to the file where diagnostic logs will be written.


## How It Works
This crypter embeds a position-independent shellcode that runs first when the PE is executed. Here's the breakdown

**API Resolution:**
*    The shellcode starts by walking the PEB (Process Environment Block) to locate loaded modules like kernel32.dll.
*    It then dynamically resolves LoadLibraryA and GetProcAddress.
*    Using those, it locates VirtualProtect, which is essential for modifying memory protections at runtime.

**Metadata Retrieval:**
*    Right after the shellcode in memory lies a LoaderMetadata structure the shellcode calculates its own instruction pointer to locate this metadata. It extracts: 
* * originalOepRva – Offset of the original entry point.
* * decryptionKey – Used for XOR decryption.
* * RVA and size info for .text, .rdata, and .data sections.

**Section Decryption:**
*    For each encrypted section:
*        Calculates its virtual address: ImageBase + SectionRVA.
*        Calls VirtualProtect to make the section writable.
*        Decrypts it in-place using XOR with decryptionKey.
*        Restores original memory protections:
*            .text → PAGE_EXECUTE_READ
*            .rdata → PAGE_READONLY
*            .data → PAGE_READWRITE

**Execution Transfer:**
    Computes the address of the original entry point: ImageBase + originalOepRva.
    Jumps to it, resuming execution of the original (now decrypted) PE.
