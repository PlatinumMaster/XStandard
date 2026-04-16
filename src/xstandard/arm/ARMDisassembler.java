package xstandard.arm;

/**
 * Disassembles ARM (32-bit) instructions into human-readable mnemonics.
 * Covers the ARMv5TE instruction set used by the NDS ARM9 and ARM7 processors.
 */
public class ARMDisassembler {

	private static final String[] DP_MNEMONICS = {
		"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC",
		"TST", "TEQ", "CMP", "CMN", "ORR", "MOV", "BIC", "MVN"
	};

	private static final String[] REG_NAMES = {
		"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
		"R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC"
	};

	private static final String[] SHIFT_NAMES = {"LSL", "LSR", "ASR", "ROR"};

	private static final String[] COND_SUFFIXES = {
		"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
		"HI", "LS", "GE", "LT", "GT", "LE", "", "NV"
	};

	/**
	 * Disassemble a single 32-bit ARM instruction.
	 *
	 * @param insn    The 32-bit instruction word (little-endian already decoded to int).
	 * @param address The memory address of this instruction (used for PC-relative targets).
	 * @return A human-readable mnemonic string.
	 */
	public static String disassemble(int insn, int address) {
		int condBits = (insn >>> 28) & 0xF;

		// Unconditional instructions (cond = 0b1111)
		if (condBits == 0xF) {
			return decodeUnconditional(insn, address);
		}

		String cond = condSuffix(condBits);
		int category = (insn >>> 25) & 0x7;

		switch (category) {
			case 0: // 000 - Data processing / multiply / misc
			case 1: // 001 - Data processing immediate
				return decodeDataProcOrMisc(insn, cond, category == 1, address);
			case 2: // 010 - Load/Store immediate offset
			case 3: // 011 - Load/Store register offset
				return decodeSingleDataTransfer(insn, cond, category == 2, address);
			case 4: // 100 - Block data transfer (LDM/STM)
				return decodeBlockDataTransfer(insn, cond);
			case 5: // 101 - Branch (B/BL)
				return decodeBranch(insn, cond, address);
			case 6: // 110 - Coprocessor data transfer
				return decodeCoprocessor(insn, cond);
			case 7: // 111 - SWI / Coprocessor
				if ((insn & (1 << 24)) != 0) {
					return decodeSWI(insn, cond);
				}
				return decodeCoprocessor(insn, cond);
			default:
				return formatUnknown(insn);
		}
	}

	// --- Category decoders ---

	private static String decodeDataProcOrMisc(int insn, String cond, boolean isImmediate, int address) {
		// Check for miscellaneous instructions when bits [24:23] = 10 and bit 20 = 0
		int opcode = (insn >>> 21) & 0xF;
		boolean sBit = ((insn >>> 20) & 1) != 0;

		if (!isImmediate) {
			// Check for BX / BLX register (bits [27:4] = 0001 0010 ... 0001)
			if ((insn & 0x0FFFFFF0) == 0x012FFF10) {
				return decodeBXReg(insn, cond);
			}
			if ((insn & 0x0FFFFFF0) == 0x012FFF30) {
				return decodeBLXReg(insn, cond);
			}

			// Check for multiply: bits [7:4] = 1001 and bits [27:22] = 000000 or 000001
			if (((insn & 0x0FC000F0) == 0x00000090)) {
				return decodeMultiply(insn, cond);
			}
			// Long multiply: bits [27:23] = 00001 and bits [7:4] = 1001
			if (((insn & 0x0F8000F0) == 0x00800090)) {
				return decodeLongMultiply(insn, cond);
			}

			// Single data swap: bits [27:20] = 00010 B 00 and bits [11:4] = 00001001
			if ((insn & 0x0FB00FF0) == 0x01000090) {
				return decodeSwap(insn, cond);
			}

			// Halfword / signed data transfer (misc loads/stores)
			// bits [7] = 1 and bits [4] = 1 and NOT multiply pattern
			if (((insn & 0x0E000090) == 0x00000090) && ((insn & 0x00000060) != 0)) {
				return decodeHalfwordTransfer(insn, cond);
			}

			// MRS: bits [27:16] = 00010 x 001111, bits [11:0] = 000000000000
			if ((insn & 0x0FBF0FFF) == 0x010F0000) {
				return decodeMRS(insn, cond);
			}
			// MSR register: bits [27:20] = 00x10 R 10
			if ((insn & 0x0FB0FFF0) == 0x0120F000) {
				return decodeMSRReg(insn, cond);
			}

			// CLZ: 0x016F0F10
			if ((insn & 0x0FFF0FF0) == 0x016F0F10) {
				int rd = (insn >>> 12) & 0xF;
				int rm = insn & 0xF;
				return "CLZ" + cond + " " + regName(rd) + ", " + regName(rm);
			}

			// BKPT
			if ((insn & 0x0FF000F0) == 0x01200070) {
				int imm = ((insn >>> 4) & 0xFFF0) | (insn & 0xF);
				return "BKPT #" + hex(imm);
			}
		} else {
			// MSR immediate: bits [27:20] = 00 I 10 R 10
			if ((insn & 0x0FB0F000) == 0x0320F000) {
				return decodeMSRImm(insn, cond);
			}
		}

		// Standard data processing
		return decodeDataProcessing(insn, cond, isImmediate, opcode, sBit);
	}

	private static String decodeDataProcessing(int insn, String cond, boolean isImmediate, int opcode, boolean sBit) {
		String mnemonic = DP_MNEMONICS[opcode];
		int rn = (insn >>> 16) & 0xF;
		int rd = (insn >>> 12) & 0xF;

		String op2 = formatOperand2(insn & 0xFFF, isImmediate);

		// Test/compare instructions (opcodes 8-11) don't write to Rd
		boolean isTest = (opcode >= 8 && opcode <= 11);
		// MOV/MVN (opcodes 13, 15) don't use Rn
		boolean isMove = (opcode == 13 || opcode == 15);

		String suffix = (sBit && !isTest) ? "S" : "";

		if (isTest) {
			// TST, TEQ, CMP, CMN: mnemonic{cond} Rn, operand2
			return mnemonic + cond + " " + regName(rn) + ", " + op2;
		} else if (isMove) {
			// MOV, MVN: mnemonic{cond}{S} Rd, operand2
			return mnemonic + cond + suffix + " " + regName(rd) + ", " + op2;
		} else {
			// Standard: mnemonic{cond}{S} Rd, Rn, operand2
			return mnemonic + cond + suffix + " " + regName(rd) + ", " + regName(rn) + ", " + op2;
		}
	}

	private static String decodeSingleDataTransfer(int insn, String cond, boolean isImmediateOffset, int address) {
		boolean preIndex = ((insn >>> 24) & 1) != 0;
		boolean up = ((insn >>> 23) & 1) != 0;
		boolean byteQty = ((insn >>> 22) & 1) != 0;
		boolean writeBack = ((insn >>> 21) & 1) != 0;
		boolean load = ((insn >>> 20) & 1) != 0;
		int rn = (insn >>> 16) & 0xF;
		int rd = (insn >>> 12) & 0xF;
		int offset = insn & 0xFFF;

		String mnemonic = load ? "LDR" : "STR";
		if (byteQty) {
			mnemonic += "B";
		}
		mnemonic += cond;

		String sign = up ? "" : "-";

		if (isImmediateOffset) {
			// Immediate offset
			if (rn == 15 && preIndex && !writeBack) {
				// PC-relative: compute absolute target
				int target = address + 8 + (up ? offset : -offset);
				return mnemonic + " " + regName(rd) + ", =" + hex(target);
			}
			if (offset == 0) {
				if (preIndex) {
					return mnemonic + " " + regName(rd) + ", [" + regName(rn) + "]";
				} else {
					return mnemonic + " " + regName(rd) + ", [" + regName(rn) + "]";
				}
			}
			String offStr = "#" + sign + hex(offset);
			if (preIndex) {
				return mnemonic + " " + regName(rd) + ", [" + regName(rn) + ", " + offStr + "]" + (writeBack ? "!" : "");
			} else {
				return mnemonic + " " + regName(rd) + ", [" + regName(rn) + "], " + offStr;
			}
		} else {
			// Register offset with optional shift
			int rm = insn & 0xF;
			int shiftType = (insn >>> 5) & 0x3;
			int shiftAmount = (insn >>> 7) & 0x1F;

			String offStr = sign + regName(rm);
			if (shiftAmount != 0 || shiftType != 0) {
				offStr += ", " + SHIFT_NAMES[shiftType] + " #" + shiftAmount;
			}

			if (preIndex) {
				return mnemonic + " " + regName(rd) + ", [" + regName(rn) + ", " + offStr + "]" + (writeBack ? "!" : "");
			} else {
				return mnemonic + " " + regName(rd) + ", [" + regName(rn) + "], " + offStr;
			}
		}
	}

	private static String decodeBlockDataTransfer(int insn, String cond) {
		boolean preIndex = ((insn >>> 24) & 1) != 0;
		boolean up = ((insn >>> 23) & 1) != 0;
		boolean psr = ((insn >>> 22) & 1) != 0;
		boolean writeBack = ((insn >>> 21) & 1) != 0;
		boolean load = ((insn >>> 20) & 1) != 0;
		int rn = (insn >>> 16) & 0xF;
		int regList = insn & 0xFFFF;

		// Use PUSH/POP aliases when base is SP with writeback
		if (rn == 13 && writeBack) {
			if (load && !preIndex && up) {
				// LDMIA SP! = POP
				return "POP" + cond + " " + formatRegisterList(regList) + (psr ? "^" : "");
			}
			if (!load && preIndex && !up) {
				// STMDB SP! = PUSH
				return "PUSH" + cond + " " + formatRegisterList(regList) + (psr ? "^" : "");
			}
		}

		String mnemonic;
		if (load) {
			mnemonic = "LDM";
		} else {
			mnemonic = "STM";
		}

		// Address mode suffix
		if (up) {
			mnemonic += preIndex ? "IB" : "IA";
		} else {
			mnemonic += preIndex ? "DB" : "DA";
		}

		return mnemonic + cond + " " + regName(rn) + (writeBack ? "!" : "") + ", " +
			formatRegisterList(regList) + (psr ? "^" : "");
	}

	private static String decodeBranch(int insn, String cond, int address) {
		boolean link = ((insn >>> 24) & 1) != 0;
		int offset = insn & 0x00FFFFFF;
		// Sign extend the 24-bit offset
		if ((offset & 0x00800000) != 0) {
			offset |= 0xFF000000;
		}
		int target = address + 8 + (offset << 2);

		return (link ? "BL" : "B") + cond + " " + hex(target);
	}

	private static String decodeBXReg(int insn, String cond) {
		int rm = insn & 0xF;
		return "BX" + cond + " " + regName(rm);
	}

	private static String decodeBLXReg(int insn, String cond) {
		int rm = insn & 0xF;
		return "BLX" + cond + " " + regName(rm);
	}

	private static String decodeMultiply(int insn, String cond) {
		boolean accumulate = ((insn >>> 21) & 1) != 0;
		boolean sBit = ((insn >>> 20) & 1) != 0;
		int rd = (insn >>> 16) & 0xF;
		int rn = (insn >>> 12) & 0xF;
		int rs = (insn >>> 8) & 0xF;
		int rm = insn & 0xF;

		String suffix = sBit ? "S" : "";
		if (accumulate) {
			return "MLA" + cond + suffix + " " + regName(rd) + ", " + regName(rm) + ", " +
				regName(rs) + ", " + regName(rn);
		} else {
			return "MUL" + cond + suffix + " " + regName(rd) + ", " + regName(rm) + ", " + regName(rs);
		}
	}

	private static String decodeLongMultiply(int insn, String cond) {
		boolean signed = ((insn >>> 22) & 1) != 0;
		boolean accumulate = ((insn >>> 21) & 1) != 0;
		boolean sBit = ((insn >>> 20) & 1) != 0;
		int rdHi = (insn >>> 16) & 0xF;
		int rdLo = (insn >>> 12) & 0xF;
		int rs = (insn >>> 8) & 0xF;
		int rm = insn & 0xF;

		String mnemonic = (signed ? "S" : "U") + (accumulate ? "MLAL" : "MULL");
		String suffix = sBit ? "S" : "";
		return mnemonic + cond + suffix + " " + regName(rdLo) + ", " + regName(rdHi) + ", " +
			regName(rm) + ", " + regName(rs);
	}

	private static String decodeSwap(int insn, String cond) {
		boolean byteQty = ((insn >>> 22) & 1) != 0;
		int rn = (insn >>> 16) & 0xF;
		int rd = (insn >>> 12) & 0xF;
		int rm = insn & 0xF;
		String mnemonic = byteQty ? "SWPB" : "SWP";
		return mnemonic + cond + " " + regName(rd) + ", " + regName(rm) + ", [" + regName(rn) + "]";
	}

	private static String decodeHalfwordTransfer(int insn, String cond) {
		boolean preIndex = ((insn >>> 24) & 1) != 0;
		boolean up = ((insn >>> 23) & 1) != 0;
		boolean isImm = ((insn >>> 22) & 1) != 0;
		boolean writeBack = ((insn >>> 21) & 1) != 0;
		boolean load = ((insn >>> 20) & 1) != 0;
		int rn = (insn >>> 16) & 0xF;
		int rd = (insn >>> 12) & 0xF;
		int sh = (insn >>> 5) & 0x3;

		String mnemonic;
		if (load) {
			switch (sh) {
				case 1: mnemonic = "LDRH"; break;
				case 2: mnemonic = "LDRSB"; break;
				case 3: mnemonic = "LDRSH"; break;
				default: mnemonic = "LDR?H"; break;
			}
		} else {
			mnemonic = (sh == 1) ? "STRH" : "STR?H";
		}
		mnemonic += cond;

		String sign = up ? "" : "-";
		String offStr;
		if (isImm) {
			int offset = ((insn >>> 4) & 0xF0) | (insn & 0xF);
			offStr = "#" + sign + hex(offset);
		} else {
			int rm = insn & 0xF;
			offStr = sign + regName(rm);
		}

		if (preIndex) {
			return mnemonic + " " + regName(rd) + ", [" + regName(rn) + ", " + offStr + "]" + (writeBack ? "!" : "");
		} else {
			return mnemonic + " " + regName(rd) + ", [" + regName(rn) + "], " + offStr;
		}
	}

	private static String decodeMRS(int insn, String cond) {
		boolean spsr = ((insn >>> 22) & 1) != 0;
		int rd = (insn >>> 12) & 0xF;
		return "MRS" + cond + " " + regName(rd) + ", " + (spsr ? "SPSR" : "CPSR");
	}

	private static String decodeMSRReg(int insn, String cond) {
		boolean spsr = ((insn >>> 22) & 1) != 0;
		int rm = insn & 0xF;
		String psr = spsr ? "SPSR" : "CPSR";
		String fields = formatPSRFields(insn);
		return "MSR" + cond + " " + psr + fields + ", " + regName(rm);
	}

	private static String decodeMSRImm(int insn, String cond) {
		boolean spsr = ((insn >>> 22) & 1) != 0;
		String psr = spsr ? "SPSR" : "CPSR";
		String fields = formatPSRFields(insn);
		int imm = ARMAssembler.decodeBarrelShiftedInt(insn & 0xFFF);
		return "MSR" + cond + " " + psr + fields + ", #" + hex(imm);
	}

	private static String formatPSRFields(int insn) {
		StringBuilder sb = new StringBuilder("_");
		if (((insn >>> 19) & 1) != 0) sb.append('f');
		if (((insn >>> 18) & 1) != 0) sb.append('s');
		if (((insn >>> 17) & 1) != 0) sb.append('x');
		if (((insn >>> 16) & 1) != 0) sb.append('c');
		return sb.length() > 1 ? sb.toString() : "";
	}

	private static String decodeSWI(int insn, String cond) {
		int imm = insn & 0x00FFFFFF;
		return "SWI" + cond + " #" + hex(imm);
	}

	private static String decodeCoprocessor(int insn, String cond) {
		// Minimal coprocessor decode
		int cpNum = (insn >>> 8) & 0xF;
		if (((insn >>> 25) & 0x7) == 0x6) {
			// Coprocessor data transfer (LDC/STC)
			boolean load = ((insn >>> 20) & 1) != 0;
			return (load ? "LDC" : "STC") + cond + " P" + cpNum + ", ...";
		}
		if (((insn >>> 24) & 0xF) == 0xE) {
			if ((insn & (1 << 4)) != 0) {
				// MRC / MCR
				boolean toARM = ((insn >>> 20) & 1) != 0;
				return (toARM ? "MRC" : "MCR") + cond + " P" + cpNum + ", ...";
			} else {
				return "CDP" + cond + " P" + cpNum + ", ...";
			}
		}
		return formatUnknown(insn);
	}

	private static String decodeUnconditional(int insn, int address) {
		// BLX immediate (cond=1111, bits [27:25] = 101)
		if (((insn >>> 25) & 0x7) == 0x5) {
			int offset = insn & 0x00FFFFFF;
			if ((offset & 0x00800000) != 0) {
				offset |= 0xFF000000;
			}
			int hBit = ((insn >>> 24) & 1);
			int target = address + 8 + (offset << 2) + (hBit << 1);
			return "BLX " + hex(target);
		}
		// PLD (cond=1111, bits [27:20] = 0101 x 101)
		if ((insn & 0x0D70F000) == 0x0550F000) {
			int rn = (insn >>> 16) & 0xF;
			int offset = insn & 0xFFF;
			boolean up = ((insn >>> 23) & 1) != 0;
			return "PLD [" + regName(rn) + ", #" + (up ? "" : "-") + hex(offset) + "]";
		}
		return formatUnknown(insn);
	}

	// --- Formatting helpers ---

	private static String regName(int reg) {
		if (reg >= 0 && reg < REG_NAMES.length) {
			return REG_NAMES[reg];
		}
		return "R" + reg;
	}

	private static String condSuffix(int condBits) {
		if (condBits >= 0 && condBits < COND_SUFFIXES.length) {
			return COND_SUFFIXES[condBits];
		}
		return "";
	}

	private static String formatOperand2(int bits, boolean isImmediate) {
		if (isImmediate) {
			int value = ARMAssembler.decodeBarrelShiftedInt(bits);
			return "#" + hex(value);
		} else {
			int rm = bits & 0xF;
			int shiftType = (bits >>> 5) & 0x3;
			boolean regShift = ((bits >>> 4) & 1) != 0;

			if (regShift) {
				int rs = (bits >>> 8) & 0xF;
				return regName(rm) + ", " + SHIFT_NAMES[shiftType] + " " + regName(rs);
			} else {
				int shiftAmount = (bits >>> 7) & 0x1F;
				if (shiftAmount == 0 && shiftType == 0) {
					return regName(rm);
				}
				if (shiftAmount == 0) {
					// Special cases: LSR #32, ASR #32 encoded as 0; ROR #0 = RRX
					if (shiftType == 3) {
						return regName(rm) + ", RRX";
					}
					shiftAmount = 32;
				}
				return regName(rm) + ", " + SHIFT_NAMES[shiftType] + " #" + shiftAmount;
			}
		}
	}

	private static String formatRegisterList(int regMask) {
		StringBuilder sb = new StringBuilder("{");
		boolean first = true;
		for (int i = 0; i < 16; i++) {
			if ((regMask & (1 << i)) != 0) {
				if (!first) {
					sb.append(", ");
				}
				sb.append(regName(i));
				first = false;
			}
		}
		sb.append("}");
		return sb.toString();
	}

	private static String hex(int value) {
		if (value < 0) {
			return "0x" + Integer.toHexString(value).toUpperCase();
		}
		return "0x" + Integer.toHexString(value).toUpperCase();
	}

	private static String formatUnknown(int insn) {
		return "DCD " + hex(insn);
	}
}
