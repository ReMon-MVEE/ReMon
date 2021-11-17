#include "shared_memory_emulation.h"
// -----------------------------------------------------------------------------------------------------------------
//      lookup table
// -----------------------------------------------------------------------------------------------------------------

constexpr const emulation_lookup instruction_intent_emulation::lookup_table[256] =
{
	{  /* 0x00 */
		&block_loader,
		&block_emulator,
	}, /* 0x00 */
	{  /* 0x01 */
		&BYTE_LOADER_NAME(0x01),
		&BYTE_EMULATOR_NAME(0x01),
	}, /* 0x01 */
	{  /* 0x02 */
		&block_loader,
		&block_emulator,
	}, /* 0x02 */
	{  /* 0x03 */
		&BYTE_LOADER_NAME(0x03),
		&BYTE_EMULATOR_NAME(0x03),
	}, /* 0x03 */
	{  /* 0x04 */
		&block_loader,
		&block_emulator,
	}, /* 0x04 */
	{  /* 0x05 */
		&block_loader,
		&block_emulator,
	}, /* 0x05 */
	{  /* 0x06 */
		&block_loader,
		&block_emulator,
	}, /* 0x06 */
	{  /* 0x07 */
		&block_loader,
		&block_emulator,
	}, /* 0x07 */
	{  /* 0x08 */
		&block_loader,
		&block_emulator,
	}, /* 0x08 */
	{  /* 0x09 */
		&block_loader,
		&block_emulator,
	}, /* 0x09 */
	{  /* 0x0a */
		&block_loader,
		&block_emulator,
	}, /* 0x0a */
	{  /* 0x0b */
		&BYTE_LOADER_NAME(0x0b),
		&BYTE_EMULATOR_NAME(0x0b),
	}, /* 0x0b */
	{  /* 0x0c */
		&block_loader,
		&block_emulator,
	}, /* 0x0c */
	{  /* 0x0d */
		&block_loader,
		&block_emulator,
	}, /* 0x0d */
	{  /* 0x0e */
		&block_loader,
		&block_emulator,
	}, /* 0x0e */
	{  /* 0x0f */
		&BYTE_LOADER_NAME(0x0f),
		&block_emulator,
	}, /* 0x0f */
	{  /* 0x10 */
		&BYTE_LOADER_NAME(0x10),
		&BYTE_EMULATOR_NAME(0x10),
	}, /* 0x10 */
	{  /* 0x11 */
		&BYTE_LOADER_NAME(0x11),
		&BYTE_EMULATOR_NAME(0x11),
	}, /* 0x11 */
	{  /* 0x12 */
		&BYTE_LOADER_NAME(0x12),
		&BYTE_EMULATOR_NAME(0x12),
	}, /* 0x12 */
	{  /* 0x13 */
		&block_loader,
		&block_emulator,
	}, /* 0x13 */
	{  /* 0x14 */
		&block_loader,
		&block_emulator,
	}, /* 0x14 */
	{  /* 0x15 */
		&block_loader,
		&block_emulator,
	}, /* 0x15 */
	{  /* 0x16 */
		&BYTE_LOADER_NAME(0x16),
		&BYTE_EMULATOR_NAME(0x16),
	}, /* 0x16 */
	{  /* 0x17 */
		&block_loader,
		&block_emulator,
	}, /* 0x17 */
	{  /* 0x18 */
		&block_loader,
		&block_emulator,
	}, /* 0x18 */
	{  /* 0x19 */
		&block_loader,
		&block_emulator,
	}, /* 0x19 */
	{  /* 0x1a */
		&block_loader,
		&block_emulator,
	}, /* 0x1a */
	{  /* 0x1b */
		&block_loader,
		&block_emulator,
	}, /* 0x1b */
	{  /* 0x1c */
		&block_loader,
		&block_emulator,
	}, /* 0x1c */
	{  /* 0x1d */
		&block_loader,
		&block_emulator,
	}, /* 0x1d */
	{  /* 0x1e */
		&block_loader,
		&block_emulator,
	}, /* 0x1e */
	{  /* 0x1f */
		&block_loader,
		&block_emulator,
	}, /* 0x1f */
	{  /* 0x20 */
		&block_loader,
		&block_emulator,
	}, /* 0x20 */
	{  /* 0x21 */
		&block_loader,
		&block_emulator,
	}, /* 0x21 */
	{  /* 0x22 */
		&block_loader,
		&block_emulator,
	}, /* 0x22 */
	{  /* 0x23 */
		&BYTE_LOADER_NAME(0x23),
		&BYTE_EMULATOR_NAME(0x23),
	}, /* 0x23 */
	{  /* 0x24 */
		&block_loader,
		&block_emulator,
	}, /* 0x24 */
	{  /* 0x25 */
		&block_loader,
		&block_emulator,
	}, /* 0x25 */
	{  /* 0x26 */
		&block_loader,
		&block_emulator,
	}, /* 0x26 */
	{  /* 0x27 */
		&block_loader,
		&block_emulator,
	}, /* 0x27 */
	{  /* 0x28 */
		&block_loader,
		&block_emulator,
	}, /* 0x28 */
	{  /* 0x29 */
		&BYTE_LOADER_NAME(0x29),
		&BYTE_EMULATOR_NAME(0x29),
	}, /* 0x29 */
	{  /* 0x2a */
		&BYTE_LOADER_NAME(0x2a),
		&BYTE_EMULATOR_NAME(0x2a),
	}, /* 0x2a */
	{  /* 0x2b */
		&BYTE_LOADER_NAME(0x2b),
		&BYTE_EMULATOR_NAME(0x2b),
	}, /* 0x2b */
	{  /* 0x2c */
		&block_loader,
		&block_emulator,
	}, /* 0x2c */
	{  /* 0x2d */
		&block_loader,
		&block_emulator,
	}, /* 0x2d */
	{  /* 0x2e */
		&block_loader,
		&block_emulator,
	}, /* 0x2e */
	{  /* 0x2f */
		&block_loader,
		&block_emulator,
	}, /* 0x2f */
	{  /* 0x30 */
		&block_loader,
		&block_emulator,
	}, /* 0x30 */
	{  /* 0x31 */
		&block_loader,
		&block_emulator,
	}, /* 0x31 */
	{  /* 0x32 */
		&block_loader,
		&block_emulator,
	}, /* 0x32 */
	{  /* 0x33 */
		&BYTE_LOADER_NAME(0x33),
		&BYTE_EMULATOR_NAME(0x33),
	}, /* 0x33 */
	{  /* 0x34 */
		&block_loader,
		&block_emulator,
	}, /* 0x34 */
	{  /* 0x35 */
		&block_loader,
		&block_emulator,
	}, /* 0x35 */
	{  /* 0x36 */
		&block_loader,
		&block_emulator,
	}, /* 0x36 */
	{  /* 0x37 */
		&block_loader,
		&block_emulator,
	}, /* 0x37 */
	{  /* 0x38 */
		&BYTE_LOADER_NAME(0x38),
		&BYTE_EMULATOR_NAME(0x38),
	}, /* 0x38 */
	{  /* 0x39 */
		&BYTE_LOADER_NAME(0x39),
		&BYTE_EMULATOR_NAME(0x39),
	}, /* 0x39 */
	{  /* 0x3a */
		&block_loader,
		&block_emulator,
	}, /* 0x3a */
	{  /* 0x3b */
		&BYTE_LOADER_NAME(0x3b),
		&BYTE_EMULATOR_NAME(0x3b),
	}, /* 0x3b */
	{  /* 0x3c */
		&block_loader,
		&block_emulator,
	}, /* 0x3c */
	{  /* 0x3d */
		&block_loader,
		&block_emulator,
	}, /* 0x3d */
	{  /* 0x3e */
		&block_loader,
		&block_emulator,
	}, /* 0x3e */
	{  /* 0x3f */
		&block_loader,
		&block_emulator,
	}, /* 0x3f */
	{  /* 0x40 */
		&BYTE_LOADER_NAME(0x40),
		&block_emulator,
	}, /* 0x40 */
	{  /* 0x41 */
		&BYTE_LOADER_NAME(0x41),
		&block_emulator,
	}, /* 0x41 */
	{  /* 0x42 */
		&BYTE_LOADER_NAME(0x42),
		&block_emulator,
	}, /* 0x42 */
	{  /* 0x43 */
		&BYTE_LOADER_NAME(0x43),
		&block_emulator,
	}, /* 0x43 */
	{  /* 0x44 */
		&BYTE_LOADER_NAME(0x44),
		&block_emulator,
	}, /* 0x44 */
	{  /* 0x45 */
		&BYTE_LOADER_NAME(0x45),
		&block_emulator,
	}, /* 0x45 */
	{  /* 0x46 */
		&BYTE_LOADER_NAME(0x46),
		&block_emulator,
	}, /* 0x46 */
	{  /* 0x47 */
		&BYTE_LOADER_NAME(0x47),
		&block_emulator,
	}, /* 0x47 */
	{  /* 0x48 */
		&BYTE_LOADER_NAME(0x48),
		&block_emulator,
	}, /* 0x48 */
	{  /* 0x49 */
		&BYTE_LOADER_NAME(0x49),
		&block_emulator,
	}, /* 0x49 */
	{  /* 0x4a */
		&BYTE_LOADER_NAME(0x4a),
		&block_emulator,
	}, /* 0x4a */
	{  /* 0x4b */
		&BYTE_LOADER_NAME(0x4b),
		&block_emulator,
	}, /* 0x4b */
	{  /* 0x4c */
		&BYTE_LOADER_NAME(0x4c),
		&block_emulator,
	}, /* 0x4c */
	{  /* 0x4d */
		&BYTE_LOADER_NAME(0x4d),
		&block_emulator,
	}, /* 0x4d */
	{  /* 0x4e */
		&BYTE_LOADER_NAME(0x4e),
		&block_emulator,
	}, /* 0x4e */
	{  /* 0x4f */
		&BYTE_LOADER_NAME(0x4f),
		&block_emulator,
	}, /* 0x4f */
	{  /* 0x50 */
		&block_loader,
		&block_emulator,
	}, /* 0x50 */
	{  /* 0x51 */
		&block_loader,
		&block_emulator,
	}, /* 0x51 */
	{  /* 0x52 */
		&block_loader,
		&block_emulator,
	}, /* 0x52 */
	{  /* 0x53 */
		&block_loader,
		&block_emulator,
	}, /* 0x53 */
	{  /* 0x54 */
		&block_loader,
		&block_emulator,
	}, /* 0x54 */
	{  /* 0x55 */
		&block_loader,
		&block_emulator,
	}, /* 0x55 */
	{  /* 0x56 */
		&block_loader,
		&block_emulator,
	}, /* 0x56 */
	{  /* 0x57 */
		&block_loader,
		&block_emulator,
	}, /* 0x57 */
	{  /* 0x58 */
		&block_loader,
		&block_emulator,
	}, /* 0x58 */
	{  /* 0x59 */
		&block_loader,
		&block_emulator,
	}, /* 0x59 */
	{  /* 0x5a */
		&block_loader,
		&block_emulator,
	}, /* 0x5a */
	{  /* 0x5b */
		&block_loader,
		&block_emulator,
	}, /* 0x5b */
	{  /* 0x5c */
		&block_loader,
		&block_emulator,
	}, /* 0x5c */
	{  /* 0x5d */
		&block_loader,
		&block_emulator,
	}, /* 0x5d */
	{  /* 0x5e */
		&block_loader,
		&block_emulator,
	}, /* 0x5e */
	{  /* 0x5f */
		&block_loader,
		&block_emulator,
	}, /* 0x5f */
	{  /* 0x60 */
		&block_loader,
		&block_emulator,
	}, /* 0x60 */
	{  /* 0x61 */
		&block_loader,
		&block_emulator,
	}, /* 0x61 */
	{  /* 0x62 */
		&block_loader,
		&block_emulator,
	}, /* 0x62 */
	{  /* 0x63 */
		&BYTE_LOADER_NAME(0x63),
		&BYTE_EMULATOR_NAME(0x63),
	}, /* 0x63 */
	{  /* 0x64 */
		&block_loader,
		&block_emulator,
	}, /* 0x64 */
	{  /* 0x65 */
		&block_loader,
		&block_emulator,
	}, /* 0x65 */
	{  /* 0x66 */
		&BYTE_LOADER_NAME(0x66),
		&block_emulator,
	}, /* 0x66 */
	{  /* 0x67 */
		&BYTE_LOADER_NAME(0x67),
		&block_emulator,
	}, /* 0x67 */
	{  /* 0x68 */
		&block_loader,
		&block_emulator,
	}, /* 0x68 */
	{  /* 0x69 */
		&block_loader,
		&block_emulator,
	}, /* 0x69 */
	{  /* 0x6a */
		&block_loader,
		&block_emulator,
	}, /* 0x6a */
	{  /* 0x6b */
		&block_loader,
		&block_emulator,
	}, /* 0x6b */
	{  /* 0x6c */
		&block_loader,
		&block_emulator,
	}, /* 0x6c */
	{  /* 0x6d */
		&block_loader,
		&block_emulator,
	}, /* 0x6d */
	{  /* 0x6e */
		&block_loader,
		&block_emulator,
	}, /* 0x6e */
	{  /* 0x6f */
		&BYTE_LOADER_NAME(0x6f),
		&BYTE_EMULATOR_NAME(0x6f),
	}, /* 0x6f */
	{  /* 0x70 */
		&block_loader,
		&block_emulator,
	}, /* 0x70 */
	{  /* 0x71 */
		&block_loader,
		&block_emulator,
	}, /* 0x71 */
	{  /* 0x72 */
		&block_loader,
		&block_emulator,
	}, /* 0x72 */
	{  /* 0x73 */
		&block_loader,
		&block_emulator,
	}, /* 0x73 */
	{  /* 0x74 */
		&BYTE_LOADER_NAME(0x74),
		&BYTE_EMULATOR_NAME(0x74),
	}, /* 0x74 */
	{  /* 0x75 */
		&block_loader,
		&block_emulator,
	}, /* 0x75 */
	{  /* 0x76 */
		&block_loader,
		&block_emulator,
	}, /* 0x76 */
	{  /* 0x77 */
		&block_loader,
		&block_emulator,
	}, /* 0x77 */
	{  /* 0x78 */
		&block_loader,
		&block_emulator,
	}, /* 0x78 */
	{  /* 0x79 */
		&block_loader,
		&block_emulator,
	}, /* 0x79 */
	{  /* 0x7a */
		&block_loader,
		&block_emulator,
	}, /* 0x7a */
	{  /* 0x7b */
		&block_loader,
		&block_emulator,
	}, /* 0x7b */
	{  /* 0x7c */
		&block_loader,
		&block_emulator,
	}, /* 0x7c */
	{  /* 0x7d */
		&block_loader,
		&block_emulator,
	}, /* 0x7d */
	{  /* 0x7e */
		&block_loader,
		&block_emulator,
	}, /* 0x7e */
	{  /* 0x7f */
		&BYTE_LOADER_NAME(0x7f),
		&BYTE_EMULATOR_NAME(0x7f),
	}, /* 0x7f */
	{  /* 0x80 */
		&BYTE_LOADER_NAME(0x80),
		&BYTE_EMULATOR_NAME(0x80),
	}, /* 0x80 */
	{  /* 0x81 */
		&BYTE_LOADER_NAME(0x81),
		&BYTE_EMULATOR_NAME(0x81),
	}, /* 0x81 */
	{  /* 0x82 */
		&block_loader,
		&block_emulator,
	}, /* 0x82 */
	{  /* 0x83 */
		&BYTE_LOADER_NAME(0x83),
		&BYTE_EMULATOR_NAME(0x83),
	}, /* 0x83 */
	{  /* 0x84 */
		&block_loader,
		&block_emulator,
	}, /* 0x84 */
	{  /* 0x85 */
		&block_loader,
		&block_emulator,
	}, /* 0x85 */
	{  /* 0x86 */
		&block_loader,
		&block_emulator,
	}, /* 0x86 */
	{  /* 0x87 */
		&BYTE_LOADER_NAME(0x87),
		&BYTE_EMULATOR_NAME(0x87),
	}, /* 0x87 */
	{  /* 0x88 */
		&BYTE_LOADER_NAME(0x88),
		&BYTE_EMULATOR_NAME(0x88),
	}, /* 0x88 */
	{  /* 0x89 */
		&BYTE_LOADER_NAME(0x89),
		&BYTE_EMULATOR_NAME(0x89),
	}, /* 0x89 */
	{  /* 0x8a */
		&BYTE_LOADER_NAME(0x8a),
		&BYTE_EMULATOR_NAME(0x8a),
	}, /* 0x8a */
	{  /* 0x8b */
		&BYTE_LOADER_NAME(0x8b),
		&BYTE_EMULATOR_NAME(0x8b),
	}, /* 0x8b */
	{  /* 0x8c */
		&BYTE_LOADER_NAME(0x8c),
		&BYTE_EMULATOR_NAME(0x8c),
	}, /* 0x8c */
	{  /* 0x8d */
		&block_loader,
		&block_emulator,
	}, /* 0x8d */
	{  /* 0x8e */
		&BYTE_LOADER_NAME(0x8e),
		&BYTE_EMULATOR_NAME(0x8e),
	}, /* 0x8e */
	{  /* 0x8f */
		&block_loader,
		&block_emulator,
	}, /* 0x8f */
	{  /* 0x90 */
		&block_loader,
		&block_emulator,
	}, /* 0x90 */
	{  /* 0x91 */
		&block_loader,
		&block_emulator,
	}, /* 0x91 */
	{  /* 0x92 */
		&block_loader,
		&block_emulator,
	}, /* 0x92 */
	{  /* 0x93 */
		&block_loader,
		&block_emulator,
	}, /* 0x93 */
	{  /* 0x94 */
		&block_loader,
		&block_emulator,
	}, /* 0x94 */
	{  /* 0x95 */
		&block_loader,
		&block_emulator,
	}, /* 0x95 */
	{  /* 0x96 */
		&block_loader,
		&block_emulator,
	}, /* 0x96 */
	{  /* 0x97 */
		&block_loader,
		&block_emulator,
	}, /* 0x97 */
	{  /* 0x98 */
		&block_loader,
		&block_emulator,
	}, /* 0x98 */
	{  /* 0x99 */
		&block_loader,
		&block_emulator,
	}, /* 0x99 */
	{  /* 0x9a */
		&block_loader,
		&block_emulator,
	}, /* 0x9a */
	{  /* 0x9b */
		&block_loader,
		&block_emulator,
	}, /* 0x9b */
	{  /* 0x9c */
		&block_loader,
		&block_emulator,
	}, /* 0x9c */
	{  /* 0x9d */
		&block_loader,
		&block_emulator,
	}, /* 0x9d */
	{  /* 0x9e */
		&block_loader,
		&block_emulator,
	}, /* 0x9e */
	{  /* 0x9f */
		&block_loader,
		&block_emulator,
	}, /* 0x9f */
	{  /* 0xa0 */
		&block_loader,
		&block_emulator,
	}, /* 0xa0 */
	{  /* 0xa1 */
		&block_loader,
		&block_emulator,
	}, /* 0xa1 */
	{  /* 0xa2 */
		&BYTE_LOADER_NAME(0xa2),
		&BYTE_EMULATOR_NAME(0xa2),
	}, /* 0xa2 */
	{  /* 0xa3 */
		&block_loader,
		&block_emulator,
	}, /* 0xa3 */
	{  /* 0xa4 */
		&BYTE_LOADER_NAME(0xa4),
		&BYTE_EMULATOR_NAME(0xa4),
	}, /* 0xa4 */
	{  /* 0xa5 */
		&block_loader,
		&block_emulator,
	}, /* 0xa5 */
	{  /* 0xa6 */
		&block_loader,
		&block_emulator,
	}, /* 0xa6 */
	{  /* 0xa7 */
		&block_loader,
		&block_emulator,
	}, /* 0xa7 */
	{  /* 0xa8 */
		&block_loader,
		&block_emulator,
	}, /* 0xa8 */
	{  /* 0xa9 */
		&block_loader,
		&block_emulator,
	}, /* 0xa9 */
	{  /* 0xaa */
		&BYTE_LOADER_NAME(0xaa),
		&BYTE_EMULATOR_NAME(0xaa),
	}, /* 0xaa */
	{  /* 0xab */
		&BYTE_LOADER_NAME(0xab),
		&BYTE_EMULATOR_NAME(0xab),
	}, /* 0xab */
	{  /* 0xac */
		&block_loader,
		&block_emulator,
	}, /* 0xac */
	{  /* 0xad */
		&block_loader,
		&block_emulator,
	}, /* 0xad */
	{  /* 0xae */
		&block_loader,
		&block_emulator,
	}, /* 0xae */
	{  /* 0xaf */
		&BYTE_LOADER_NAME(0xaf),
		&BYTE_EMULATOR_NAME(0xaf),
	}, /* 0xaf */
	{  /* 0xb0 */
		&block_loader,
		&block_emulator,
	}, /* 0xb0 */
	{  /* 0xb1 */
		&BYTE_LOADER_NAME(0xb1),
		&BYTE_EMULATOR_NAME(0xb1),
	}, /* 0xb1 */
	{  /* 0xb2 */
		&block_loader,
		&block_emulator,
	}, /* 0xb2 */
	{  /* 0xb3 */
		&block_loader,
		&block_emulator,
	}, /* 0xb3 */
	{  /* 0xb4 */
		&block_loader,
		&block_emulator,
	}, /* 0xb4 */
	{  /* 0xb5 */
		&block_loader,
		&block_emulator,
	}, /* 0xb5 */
	{  /* 0xb6 */
		&BYTE_LOADER_NAME(0xb6),
		&BYTE_EMULATOR_NAME(0xb6),
	}, /* 0xb6 */
	{  /* 0xb7 */
		&BYTE_LOADER_NAME(0xb7),
		&BYTE_EMULATOR_NAME(0xb7),
	}, /* 0xb7 */
	{  /* 0xb8 */
		&block_loader,
		&block_emulator,
	}, /* 0xb8 */
	{  /* 0xb9 */
		&block_loader,
		&block_emulator,
	}, /* 0xb9 */
	{  /* 0xba */
		&block_loader,
		&block_emulator,
	}, /* 0xba */
	{  /* 0xbb */
		&block_loader,
		&block_emulator,
	}, /* 0xbb */
	{  /* 0xbc */
		&block_loader,
		&block_emulator,
	}, /* 0xbc */
	{  /* 0xbd */
		&block_loader,
		&block_emulator,
	}, /* 0xbd */
	{  /* 0xbe */
		&BYTE_LOADER_NAME(0xbe),
		&BYTE_EMULATOR_NAME(0xbe),
	}, /* 0xbe */
	{  /* 0xbf */
		&block_loader,
		&block_emulator,
	}, /* 0xbf */
	{  /* 0xc0 */
		&block_loader,
		&block_emulator,
	}, /* 0xc0 */
	{  /* 0xc1 */
		&BYTE_LOADER_NAME(0xc1),
		&BYTE_EMULATOR_NAME(0xc1),
	}, /* 0xc1 */
	{  /* 0xc2 */
		&block_loader,
		&block_emulator,
	}, /* 0xc2 */
	{  /* 0xc3 */
		&block_loader,
		&block_emulator,
	}, /* 0xc3 */
	{  /* 0xc4 */
		&BYTE_LOADER_NAME(0xc4),
		&block_emulator,
	}, /* 0xc4 */
	{  /* 0xc5 */
		&BYTE_LOADER_NAME(0xc5),
		&block_emulator,
	}, /* 0xc5 */
	{  /* 0xc6 */
		&BYTE_LOADER_NAME(0xc6),
		&BYTE_EMULATOR_NAME(0xc6),
	}, /* 0xc6 */
	{  /* 0xc7 */
		&BYTE_LOADER_NAME(0xc7),
		&BYTE_EMULATOR_NAME(0xc7),
	}, /* 0xc7 */
	{  /* 0xc8 */
		&block_loader,
		&block_emulator,
	}, /* 0xc8 */
	{  /* 0xc9 */
		&block_loader,
		&block_emulator,
	}, /* 0xc9 */
	{  /* 0xca */
		&block_loader,
		&block_emulator,
	}, /* 0xca */
	{  /* 0xcb */
		&block_loader,
		&block_emulator,
	}, /* 0xcb */
	{  /* 0xcc */
		&block_loader,
		&block_emulator,
	}, /* 0xcc */
	{  /* 0xcd */
		&block_loader,
		&block_emulator,
	}, /* 0xcd */
	{  /* 0xce */
		&block_loader,
		&block_emulator,
	}, /* 0xce */
	{  /* 0xcf */
		&block_loader,
		&block_emulator,
	}, /* 0xcf */
	{  /* 0xd0 */
		&block_loader,
		&block_emulator,
	}, /* 0xd0 */
	{  /* 0xd1 */
		&block_loader,
		&block_emulator,
	}, /* 0xd1 */
	{  /* 0xd2 */
		&block_loader,
		&block_emulator,
	}, /* 0xd2 */
	{  /* 0xd3 */
		&block_loader,
		&block_emulator,
	}, /* 0xd3 */
	{  /* 0xd4 */
		&block_loader,
		&block_emulator,
	}, /* 0xd4 */
	{  /* 0xd5 */
		&block_loader,
		&block_emulator,
	}, /* 0xd5 */
	{  /* 0xd6 */
		&block_loader,
		&block_emulator,
	}, /* 0xd6 */
	{  /* 0xd7 */
		&block_loader,
		&block_emulator,
	}, /* 0xd7 */
	{  /* 0xd8 */
		&block_loader,
		&block_emulator,
	}, /* 0xd8 */
	{  /* 0xd9 */
		&block_loader,
		&block_emulator,
	}, /* 0xd9 */
	{  /* 0xda */
		&BYTE_LOADER_NAME(0xda),
		&BYTE_EMULATOR_NAME(0xda),
	}, /* 0xda */
	{  /* 0xdb */
		&block_loader,
		&block_emulator,
	}, /* 0xdb */
	{  /* 0xdc */
		&block_loader,
		&block_emulator,
	}, /* 0xdc */
	{  /* 0xdd */
		&block_loader,
		&block_emulator,
	}, /* 0xdd */
	{  /* 0xde */
		&block_loader,
		&block_emulator,
	}, /* 0xde */
	{  /* 0xdf */
		&block_loader,
		&block_emulator,
	}, /* 0xdf */
	{  /* 0xe0 */
		&block_loader,
		&block_emulator,
	}, /* 0xe0 */
	{  /* 0xe1 */
		&block_loader,
		&block_emulator,
	}, /* 0xe1 */
	{  /* 0xe2 */
		&block_loader,
		&block_emulator,
	}, /* 0xe2 */
	{  /* 0xe3 */
		&block_loader,
		&block_emulator,
	}, /* 0xe3 */
	{  /* 0xe4 */
		&block_loader,
		&block_emulator,
	}, /* 0xe4 */
	{  /* 0xe5 */
		&block_loader,
		&block_emulator,
	}, /* 0xe5 */
	{  /* 0xe6 */
		&block_loader,
		&block_emulator,
	}, /* 0xe6 */
	{  /* 0xe7 */
		&BYTE_LOADER_NAME(0xe7),
		&BYTE_EMULATOR_NAME(0xe7),
	}, /* 0xe7 */
	{  /* 0xe8 */
		&block_loader,
		&block_emulator,
	}, /* 0xe8 */
	{  /* 0xe9 */
		&block_loader,
		&block_emulator,
	}, /* 0xe9 */
	{  /* 0xea */
		&block_loader,
		&block_emulator,
	}, /* 0xea */
	{  /* 0xeb */
		&block_loader,
		&block_emulator,
	}, /* 0xeb */
	{  /* 0xec */
		&block_loader,
		&block_emulator,
	}, /* 0xec */
	{  /* 0xed */
		&block_loader,
		&block_emulator,
	}, /* 0xed */
	{  /* 0xee */
		&block_loader,
		&block_emulator,
	}, /* 0xee */
	{  /* 0xef */
		&block_loader,
		&block_emulator,
	}, /* 0xef */
	{  /* 0xf0 */
		&BYTE_LOADER_NAME(0xf0),
		&block_emulator,
	}, /* 0xf0 */
	{  /* 0xf1 */
		&block_loader,
		&block_emulator,
	}, /* 0xf1 */
	{  /* 0xf2 */
		&BYTE_LOADER_NAME(0xf2),
		&block_emulator,
	}, /* 0xf2 */
	{  /* 0xf3 */
		&BYTE_LOADER_NAME(0xf3),
		&block_emulator,
	}, /* 0xf3 */
	{  /* 0xf4 */
		&block_loader,
		&block_emulator,
	}, /* 0xf4 */
	{  /* 0xf5 */
		&block_loader,
		&block_emulator,
	}, /* 0xf5 */
	{  /* 0xf6 */
		&BYTE_LOADER_NAME(0xf6),
		&BYTE_EMULATOR_NAME(0xf6),
	}, /* 0xf6 */
	{  /* 0xf7 */
		&block_loader,
		&block_emulator,
	}, /* 0xf7 */
	{  /* 0xf8 */
		&block_loader,
		&block_emulator,
	}, /* 0xf8 */
	{  /* 0xf9 */
		&block_loader,
		&block_emulator,
	}, /* 0xf9 */
	{  /* 0xfa */
		&block_loader,
		&block_emulator,
	}, /* 0xfa */
	{  /* 0xfb */
		&block_loader,
		&block_emulator,
	}, /* 0xfb */
	{  /* 0xfc */
		&block_loader,
		&block_emulator,
	}, /* 0xfc */
	{  /* 0xfd */
		&block_loader,
		&block_emulator,
	}, /* 0xfd */
	{  /* 0xfe */
		&block_loader,
		&block_emulator,
	}, /* 0xfe */
	{  /* 0xff */
		&block_loader,
		&block_emulator,
	}, /* 0xff */
};