/*
 *  Copyright 2017 Vladimir Panteleev <vladimir@thecybershadow.net>
 *  This file is part of rclidasm.
 *
 *  rclidasm is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  rclidasm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with rclidasm.  If not, see <http://www.gnu.org/licenses/>.
 */

module rclidasm.representation;

import std.conv;
import std.datetime;
import std.string;
import std.traits;

import ae.sys.windows.imports;
import ae.utils.array;
import ae.utils.time.format;
import ae.utils.time.parse;

mixin(importWin32!(q{winnt}));

import rclidasm.assembler;
import rclidasm.clifile;
import rclidasm.common;
import rclidasm.disassembler;

struct DefaultRepresentation {}

struct HexIntegerRepresentation {}

/// For zero-terminated strings in fixed-length arrays.
struct CStrArrRepresentation {}

/// Constants which are not declared as an actual enum.
struct ImplicitEnumRepresentation(members...) {}

/// An array which might as well be a struct with all fields of the same type.
/// Note: the array length is not represented (because entries with
/// default values are omitted), and must be fixed or specified elsewhere.
struct SparseNamedIndexedArrayRepresentation(members...) {}

/// Bitmask using constants which are not declared as an actual enum.
struct ImplicitEnumBitmaskRepresentation(members...) {}

/// Unix timestamp Representation.
struct UnixTimestampRepresentation
{
	enum timeFormat = "Y-m-d H:i:s";
}

/// Representation for unions. fieldIndex indicates the index of the union
/// field we will be looking at.
struct UnionRepresentation(uint fieldIndex) {}

template RepresentationOf(P, F, string name)
{
	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "TimeDateStamp")
		alias RepresentationOf = UnixTimestampRepresentation;
	else
	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "SizeOfOptionalHeader")
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "Characteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
			IMAGE_FILE_RELOCS_STRIPPED,
			IMAGE_FILE_EXECUTABLE_IMAGE,
			IMAGE_FILE_LINE_NUMS_STRIPPED,
			IMAGE_FILE_LOCAL_SYMS_STRIPPED,
			IMAGE_FILE_AGGRESIVE_WS_TRIM,
			IMAGE_FILE_LARGE_ADDRESS_AWARE,
			IMAGE_FILE_BYTES_REVERSED_LO,
			IMAGE_FILE_32BIT_MACHINE,
			IMAGE_FILE_DEBUG_STRIPPED,
			IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
			IMAGE_FILE_NET_RUN_FROM_SWAP,
			IMAGE_FILE_SYSTEM,
			IMAGE_FILE_DLL,
			IMAGE_FILE_UP_SYSTEM_ONLY,
			IMAGE_FILE_BYTES_REVERSED_HI,
		);
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name.isOneOf("SizeOfCode", "SizeOfInitializedData",
			"AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "SizeOfImage", "SizeOfHeaders"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name == "Subsystem")
		alias RepresentationOf = ImplicitEnumRepresentation!(
			IMAGE_SUBSYSTEM_UNKNOWN,
			IMAGE_SUBSYSTEM_NATIVE,
			IMAGE_SUBSYSTEM_WINDOWS_GUI,
			IMAGE_SUBSYSTEM_WINDOWS_CUI,
			IMAGE_SUBSYSTEM_OS2_CUI,
			IMAGE_SUBSYSTEM_POSIX_CUI,
			IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
			IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
			IMAGE_SUBSYSTEM_EFI_APPLICATION,
			IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
			IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
			IMAGE_SUBSYSTEM_EFI_ROM,
			IMAGE_SUBSYSTEM_XBOX,
			IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
		);
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name == "DllCharacteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
			IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
			IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
			IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
			IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
			IMAGE_DLLCHARACTERISTICS_NO_SEH	,
			IMAGE_DLLCHARACTERISTICS_NO_BIND,
			IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
		);
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Characteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
			IMAGE_SCN_TYPE_REG,
			IMAGE_SCN_TYPE_DSECT,
			IMAGE_SCN_TYPE_NOLOAD,
			IMAGE_SCN_TYPE_GROUP,
			IMAGE_SCN_TYPE_NO_PAD,
			IMAGE_SCN_TYPE_COPY,
			IMAGE_SCN_CNT_CODE,
			IMAGE_SCN_CNT_INITIALIZED_DATA,
			IMAGE_SCN_CNT_UNINITIALIZED_DATA,
			IMAGE_SCN_LNK_OTHER,
			IMAGE_SCN_LNK_INFO,
			IMAGE_SCN_TYPE_OVER,
			IMAGE_SCN_LNK_REMOVE,
			IMAGE_SCN_LNK_COMDAT,
			IMAGE_SCN_MEM_FARDATA,
			IMAGE_SCN_GPREL,
			IMAGE_SCN_MEM_PURGEABLE,
		//	IMAGE_SCN_MEM_16BIT,
			IMAGE_SCN_MEM_LOCKED,
			IMAGE_SCN_MEM_PRELOAD,
			IMAGE_SCN_LNK_NRELOC_OVFL,
			IMAGE_SCN_MEM_DISCARDABLE,
			IMAGE_SCN_MEM_NOT_CACHED,
			IMAGE_SCN_MEM_NOT_PAGED,
			IMAGE_SCN_MEM_SHARED,
			IMAGE_SCN_MEM_EXECUTE,
			IMAGE_SCN_MEM_READ,
			IMAGE_SCN_MEM_WRITE,

			// These bits are not a bitmask, so sort them from most to least bits,
			// so that the member with most bits gets used first
			// 3 bits
			IMAGE_SCN_ALIGN_64BYTES,          // 0x00700000
			IMAGE_SCN_ALIGN_1024BYTES,        // 0x00B00000
			IMAGE_SCN_ALIGN_4096BYTES,        // 0x00D00000
			IMAGE_SCN_ALIGN_8192BYTES,        // 0x00E00000
			// 2 bits
			IMAGE_SCN_ALIGN_4BYTES,           // 0x00300000
			IMAGE_SCN_ALIGN_16BYTES,          // 0x00500000
			IMAGE_SCN_ALIGN_32BYTES,          // 0x00600000
			IMAGE_SCN_ALIGN_256BYTES,         // 0x00900000
			IMAGE_SCN_ALIGN_512BYTES,         // 0x00A00000
			IMAGE_SCN_ALIGN_2048BYTES,        // 0x00C00000
			// 1 bit
			IMAGE_SCN_ALIGN_1BYTES,           // 0x00100000
			IMAGE_SCN_ALIGN_2BYTES,           // 0x00200000
			IMAGE_SCN_ALIGN_8BYTES,           // 0x00400000
			IMAGE_SCN_ALIGN_128BYTES,         // 0x00800000
		);
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Name")
		alias RepresentationOf = CStrArrRepresentation;
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name.isOneOf("VirtualAddress", "SizeOfRawData", "PointerToRawData"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Misc")
		alias RepresentationOf = UnionRepresentation!1; // VirtualSize
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER._Misc) && name == "VirtualSize")
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == CLIFile.Header) && name == "dataDirectories")
		alias RepresentationOf = SparseNamedIndexedArrayRepresentation!(
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			IMAGE_DIRECTORY_ENTRY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_RESOURCE,
			IMAGE_DIRECTORY_ENTRY_EXCEPTION,
			IMAGE_DIRECTORY_ENTRY_SECURITY,
			IMAGE_DIRECTORY_ENTRY_BASERELOC,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
			IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
			IMAGE_DIRECTORY_ENTRY_TLS,
			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
			IMAGE_DIRECTORY_ENTRY_IAT,
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
		);
	else
	static if (is(Unqual!P == IMAGE_DATA_DIRECTORY) && name.isOneOf("VirtualAddress", "Size"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == CLIFile.UnaccountedBlock) && name == "offset")
		alias RepresentationOf = HexIntegerRepresentation;
	else
		alias RepresentationOf = DefaultRepresentation;
}
