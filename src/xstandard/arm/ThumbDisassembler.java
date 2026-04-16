package xstandard.arm;

/**
 * Disassembles Thumb (16-bit) instructions into human-readable mnemonics.
 * Covers the Thumb instruction set used by the NDS ARM9 and ARM7 processors.
 * BL/BLX are 32-bit (two halfwords); use {@link #disassembleLong} for those.
 */
public class ThumbDisassembler {

	private static final String[] REG_NAMES = {
		"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
		"R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC"
	};

	private static final String[] ALU_MNEMONICS = {
		"AND", "EOR", "LSL", "LSR", "ASR", "ADC", "SBC", "ROR",
		"TST", "NEG", "CMP", "CMN", "ORR", "MUL", "BIC", "MVN"
	};

	private static final String[] COND_SUFFIXES = {
		"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
		"HI", "LS", "GE", "LT", "GT", "LE"
	};

	/**
	 * Check if this halfword is the first half of a 32-bit Thumb instruction (BL/BLX prefix).
	 */
	public static boolean isLongBranchPrefix(int halfword) {
		return (halfword & ThumbAssembler.BL_MASK) == ThumbAssembler.BL_HIGH_IDENT;
	}

	/**
	 * Disassemble a single 16-bit Thumb instruction.
	 * If this is a BL/BLX prefix halfword, returns a partial representation.
	 * Use {@link #disassembleLong} for the full 32-bit BL/BLX.
	 *
	 * @param hw      The 16-bit instruction halfword.
	 * @param address The memory address of this instruction.
	 * @return A human-readable mnemonic string.
	 */
	public static String disassemble(int hw, int address) {
		hw &= 0xFFFF;

		int top3 = (hw >>> 13) & 0x7;

		switch (top3) {
			case 0: // 000 - Format 1 (shift) or Format 2 (add/sub)
				if (((hw >>> 11) & 0x3) == 0x3) {
					return decodeAddSub(hw);
				}
				return decodeMoveShiftedReg(hw);

			case 1: // 001 - Format 3 (immediate ops)
				return decodeImmOps(hw);

			case 2: // 010 - Formats 4-8
				return decodeGroup010(hw, address);

			case 3: // 011 - Format 9 (LDR/STR imm offset)
				return decodeLoadStoreImmOffset(hw);

			case 4: // 100 - Format 10 (LDRH/STRH imm) or Format 11 (SP-relative)
				if (((hw >>> 12) & 1) == 0) {
					return decodeLoadStoreHalf(hw);
				} else {
					return decodeSPRelativeLoadStore(hw);
				}

			case 5: // 101 - Formats 12-14
				return decodeGroup101(hw, address);

			case 6: // 110 - Format 16 (conditional branch) or Format 17 (SWI)
				return decodeGroup110(hw, address);

			case 7: // 111 - Format 18 (unconditional branch) or BL/BLX prefix
				if (isLongBranchPrefix(hw)) {
					return "BL/BLX (prefix)";
				}
				if (((hw >>> 11) & 0x1F) == 0x1C) {
					return decodeUnconditionalBranch(hw, address);
				}
				// Second half of BL/BLX appearing without prefix
				return "DCD " + hex4(hw);

			default:
				return "DCD " + hex4(hw);
		}
	}

	/**
	 * Disassemble a 32-bit Thumb instruction (BL/BLX) from two consecutive halfwords.
	 *
	 * @param first   The first halfword (BL_HIGH_IDENT prefix).
	 * @param second  The second halfword (BL_LOW_IDENT or BLX_LOW_IDENT).
	 * @param address The memory address of the first halfword.
	 * @return A human-readable mnemonic string.
	 */
	public static String disassembleLong(int first, int second, int address) {
		first &= 0xFFFF;
		second &= 0xFFFF;

		int highBits = first & 0x7FF;
		int lowBits = second & 0x7FF;
		// Sign-extend the high 11 bits
		int offset = ((highBits << 21) >> 10) | lowBits;
		int target = (address + 4) + (offset << 1);

		boolean exchange = (second & ThumbAssembler.BL_MASK) == ThumbAssembler.BLX_LOW_IDENT;
		if (exchange) {
			target &= ~3; // BLX aligns to word boundary
			return "BLX " + hex(target);
		} else {
			return "BL " + hex(target);
		}
	}

	// --- Format decoders ---

	// Format 1: Move shifted register - LSL/LSR/ASR Rd, Rs, #Offset5
	private static String decodeMoveShiftedReg(int hw) {
		int op = (hw >>> 11) & 0x3;
		int offset = (hw >>> 6) & 0x1F;
		int rs = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String[] ops = {"LSL", "LSR", "ASR"};
		String mnemonic = (op < 3) ? ops[op] : "???";

		// LSR #0 and ASR #0 encode as #32
		if (offset == 0 && (op == 1 || op == 2)) {
			offset = 32;
		}

		return mnemonic + " " + regName(rd) + ", " + regName(rs) + ", #" + offset;
	}

	// Format 2: ADD/SUB Rd, Rs, Rn/#imm3
	private static String decodeAddSub(int hw) {
		boolean isImm = ((hw >>> 10) & 1) != 0;
		boolean isSub = ((hw >>> 9) & 1) != 0;
		int rnOrImm = (hw >>> 6) & 0x7;
		int rs = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String mnemonic = isSub ? "SUB" : "ADD";
		if (isImm) {
			return mnemonic + " " + regName(rd) + ", " + regName(rs) + ", #" + rnOrImm;
		} else {
			return mnemonic + " " + regName(rd) + ", " + regName(rs) + ", " + regName(rnOrImm);
		}
	}

	// Format 3: MOV/CMP/ADD/SUB Rd, #imm8
	private static String decodeImmOps(int hw) {
		int op = (hw >>> 11) & 0x3;
		int rd = (hw >>> 8) & 0x7;
		int imm = hw & 0xFF;

		String[] ops = {"MOV", "CMP", "ADD", "SUB"};
		return ops[op] + " " + regName(rd) + ", #" + hex(imm);
	}

	// Group 010: Formats 4, 5, 6, 7, 8
	private static String decodeGroup010(int hw, int address) {
		if (((hw >>> 10) & 0x7) == 0x4) {
			// Format 4: ALU operations
			return decodeALUOps(hw);
		}
		if (((hw >>> 10) & 0x7) == 0x5) {
			// Format 5: Hi register operations / BX
			return decodeHiRegBX(hw);
		}
		if (((hw >>> 11) & 0x1F) == 0x9) {
			// Format 6: PC-relative load
			return decodePCRelativeLoad(hw, address);
		}
		// Formats 7 and 8
		if (((hw >>> 9) & 1) == 0) {
			return decodeLoadStoreRegOffset(hw);
		} else {
			return decodeLoadStoreSignExtend(hw);
		}
	}

	// Format 4: ALU operations
	private static String decodeALUOps(int hw) {
		int op = (hw >>> 6) & 0xF;
		int rs = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;
		return ALU_MNEMONICS[op] + " " + regName(rd) + ", " + regName(rs);
	}

	// Format 5: Hi register operations / BX
	private static String decodeHiRegBX(int hw) {
		int op = (hw >>> 8) & 0x3;
		boolean h1 = ((hw >>> 7) & 1) != 0;
		boolean h2 = ((hw >>> 6) & 1) != 0;
		int rs = ((h2 ? 8 : 0) | ((hw >>> 3) & 0x7));
		int rd = ((h1 ? 8 : 0) | (hw & 0x7));

		switch (op) {
			case 0:
				return "ADD " + regName(rd) + ", " + regName(rs);
			case 1:
				return "CMP " + regName(rd) + ", " + regName(rs);
			case 2:
				return "MOV " + regName(rd) + ", " + regName(rs);
			case 3:
				if (h1) {
					return "BLX " + regName(rs);
				}
				return "BX " + regName(rs);
			default:
				return "DCD " + hex4(hw);
		}
	}

	// Format 6: PC-relative load - LDR Rd, [PC, #imm8*4]
	private static String decodePCRelativeLoad(int hw, int address) {
		int rd = (hw >>> 8) & 0x7;
		int offset = (hw & 0xFF) << 2;
		// PC is aligned to 4 in Thumb mode for this instruction
		int base = (address + 4) & ~3;
		int target = base + offset;
		return "LDR " + regName(rd) + ", =" + hex(target);
	}

	// Format 7: Load/Store with register offset
	private static String decodeLoadStoreRegOffset(int hw) {
		boolean load = ((hw >>> 11) & 1) != 0;
		boolean byteQty = ((hw >>> 10) & 1) != 0;
		int ro = (hw >>> 6) & 0x7;
		int rb = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String mnemonic;
		if (load) {
			mnemonic = byteQty ? "LDRB" : "LDR";
		} else {
			mnemonic = byteQty ? "STRB" : "STR";
		}
		return mnemonic + " " + regName(rd) + ", [" + regName(rb) + ", " + regName(ro) + "]";
	}

	// Format 8: Load/Store sign-extended byte/halfword
	private static String decodeLoadStoreSignExtend(int hw) {
		int op = (hw >>> 10) & 0x3;
		int ro = (hw >>> 6) & 0x7;
		int rb = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String[] mnemonics = {"STRH", "LDSB", "LDRH", "LDSH"};
		return mnemonics[op] + " " + regName(rd) + ", [" + regName(rb) + ", " + regName(ro) + "]";
	}

	// Format 9: Load/Store with immediate offset
	private static String decodeLoadStoreImmOffset(int hw) {
		boolean byteQty = ((hw >>> 12) & 1) != 0;
		boolean load = ((hw >>> 11) & 1) != 0;
		int offset = (hw >>> 6) & 0x1F;
		int rb = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String mnemonic;
		if (load) {
			mnemonic = byteQty ? "LDRB" : "LDR";
		} else {
			mnemonic = byteQty ? "STRB" : "STR";
		}

		// Word transfers have offset * 4
		if (!byteQty) {
			offset <<= 2;
		}

		return mnemonic + " " + regName(rd) + ", [" + regName(rb) + ", #" + hex(offset) + "]";
	}

	// Format 10: Load/Store halfword with immediate offset
	private static String decodeLoadStoreHalf(int hw) {
		boolean load = ((hw >>> 11) & 1) != 0;
		int offset = ((hw >>> 6) & 0x1F) << 1;
		int rb = (hw >>> 3) & 0x7;
		int rd = hw & 0x7;

		String mnemonic = load ? "LDRH" : "STRH";
		return mnemonic + " " + regName(rd) + ", [" + regName(rb) + ", #" + hex(offset) + "]";
	}

	// Format 11: SP-relative Load/Store
	private static String decodeSPRelativeLoadStore(int hw) {
		boolean load = ((hw >>> 11) & 1) != 0;
		int rd = (hw >>> 8) & 0x7;
		int offset = (hw & 0xFF) << 2;

		String mnemonic = load ? "LDR" : "STR";
		return mnemonic + " " + regName(rd) + ", [SP, #" + hex(offset) + "]";
	}

	// Group 101: Formats 12, 13, 14
	private static String decodeGroup101(int hw, int address) {
		if (((hw >>> 12) & 1) == 0) {
			// Format 12: Load address (ADD Rd, PC/SP, #imm8*4)
			return decodeLoadAddress(hw, address);
		}

		// Check for Format 13: Adjust SP
		if (((hw >>> 8) & 0xFF) == 0xB0 || ((hw >>> 8) & 0xFF) == 0xB1) {
			// ADD SP, #imm / SUB SP, #imm
			return decodeAdjustSP(hw);
		}
		// Also check the broader pattern for adjust SP
		if (((hw >>> 8) & 0xF) == 0x0 && ((hw >>> 12) & 0xF) == 0xB) {
			return decodeAdjustSP(hw);
		}

		// Format 14: Push/Pop
		if (((hw >>> 12) & 0xF) == 0xB) {
			int subOp = (hw >>> 9) & 0x3;
			if (subOp == 0x2 || subOp == 0x3) {
				// PUSH / POP
				return decodePushPop(hw);
			}
			// BKPT
			if (((hw >>> 8) & 0xFF) == 0xBE) {
				int imm = hw & 0xFF;
				return "BKPT #" + hex(imm);
			}
			return decodeAdjustSP(hw);
		}

		return "DCD " + hex4(hw);
	}

	// Format 12: Load address - ADD Rd, PC/SP, #imm8*4
	private static String decodeLoadAddress(int hw, int address) {
		boolean useSP = ((hw >>> 11) & 1) != 0;
		int rd = (hw >>> 8) & 0x7;
		int offset = (hw & 0xFF) << 2;

		if (useSP) {
			return "ADD " + regName(rd) + ", SP, #" + hex(offset);
		} else {
			int base = (address + 4) & ~3;
			int target = base + offset;
			return "ADD " + regName(rd) + ", PC, #" + hex(offset) + " ; =" + hex(target);
		}
	}

	// Format 13: Adjust SP - ADD SP, #imm7*4 / SUB SP, #imm7*4
	private static String decodeAdjustSP(int hw) {
		boolean negative = ((hw >>> 7) & 1) != 0;
		int offset = (hw & 0x7F) << 2;
		return (negative ? "SUB" : "ADD") + " SP, #" + hex(offset);
	}

	// Format 14: Push/Pop
	private static String decodePushPop(int hw) {
		boolean pop = ((hw >>> 11) & 1) != 0;
		boolean extraReg = ((hw >>> 8) & 1) != 0; // LR for PUSH, PC for POP
		int regList = hw & 0xFF;

		StringBuilder sb = new StringBuilder(pop ? "POP {" : "PUSH {");
		boolean first = true;

		for (int i = 0; i < 8; i++) {
			if ((regList & (1 << i)) != 0) {
				if (!first) sb.append(", ");
				sb.append(regName(i));
				first = false;
			}
		}

		if (extraReg) {
			if (!first) sb.append(", ");
			sb.append(pop ? "PC" : "LR");
		}

		sb.append("}");
		return sb.toString();
	}

	// Group 110: Format 16 (conditional branch), Format 17 (SWI)
	private static String decodeGroup110(int hw, int address) {
		int condBits = (hw >>> 8) & 0xF;

		if (condBits == 0xF) {
			// Format 17: SWI
			int imm = hw & 0xFF;
			return "SWI #" + hex(imm);
		}
		if (condBits == 0xE) {
			// Undefined
			return "DCD " + hex4(hw);
		}

		// Format 16: Conditional branch
		int offset = hw & 0xFF;
		// Sign extend 8-bit offset
		if ((offset & 0x80) != 0) {
			offset |= 0xFFFFFF00;
		}
		int target = address + 4 + (offset << 1);

		String cond = (condBits < COND_SUFFIXES.length) ? COND_SUFFIXES[condBits] : "??";
		return "B" + cond + " " + hex(target);
	}

	// Format 18: Unconditional branch - B #offset11
	private static String decodeUnconditionalBranch(int hw, int address) {
		int offset = hw & 0x7FF;
		// Sign extend 11-bit offset
		if ((offset & 0x400) != 0) {
			offset |= 0xFFFFF800;
		}
		int target = address + 4 + (offset << 1);
		return "B " + hex(target);
	}

	// --- Helpers ---

	private static String regName(int reg) {
		if (reg >= 0 && reg < REG_NAMES.length) {
			return REG_NAMES[reg];
		}
		return "R" + reg;
	}

	private static String hex(int value) {
		if (value < 0) {
			return "0x" + Integer.toHexString(value).toUpperCase();
		}
		return "0x" + Integer.toHexString(value).toUpperCase();
	}

	private static String hex4(int value) {
		return "0x" + String.format("%04X", value & 0xFFFF);
	}
}
