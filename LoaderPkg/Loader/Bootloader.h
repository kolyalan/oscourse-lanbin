/** @file
  Copyright (c) 2020, ISP RAS. All rights reserved.
  SPDX-License-Identifier: BSD-3-Clause
**/

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/FileHandleLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseCryptLib.h>

#include <Protocol/GraphicsOutput.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextOut.h>
#include <Guid/ImageAuthentication.h>

#include "Elf64.h"

#include <LoaderParams.h>

extern UINT8 Hash[];
///
/// Kernel path.
///
#define KERNEL_PATH L"\\EFI\\BOOT\\kernel"
#define HASH_SIZE SHA256_DIGEST_SIZE

/**
  Generate architecture-specific kernel call gate data.

  @param[out] GateData   Pointer to gate data pointer.

  @retval EFI_SUCCESS on success.
**/
EFI_STATUS
GenerateGateData (
  OUT VOID **GateData
  );

/**
  Call kernel through architecture gate.
  Does not return on success.

  @param[in]  EntryPoint     Kernel entry point.
  @param[in]  LoaderParams   Kernel loader params.
  @param[in]  GateData       Arch kernel call gate data.
**/
VOID
EFIAPI
CallKernelThroughGate (
  IN UINTN          EntryPoint,
  IN LOADER_PARAMS  *LoaderParams,
  IN VOID           *GateData
  );

/**
  Kernel entry point prototype.
**/
typedef
VOID
(EFIAPI *KERNEL_ENTRY) (
  IN LOADER_PARAMS  *LoaderParams,
  IN VOID           *GateData
  );

#endif // BOOTLOADER_H
