//! Bitcoin script execution data types.
//!
//! This module provides types for representing and inspecting Bitcoin script
//! execution state: opcodes, script instructions, stack items, and script phases.
//!
//! These types are pure data — they have no FFI dependencies and can be used
//! independently of the debugger callback infrastructure.

use std::fmt;

// ─── Opcode ─────────────────────────────────────────────────────────────────

/// A decoded Bitcoin script opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // Push values
    Op0,
    PushBytes(u8), // 1..=75
    PushData1,
    PushData2,
    PushData4,
    Op1Negate,
    OpReserved,
    OpNum(u8), // OP_1..OP_16 (value 1..16)

    // Flow control
    OpNop,
    OpVer,
    OpIf,
    OpNotIf,
    OpVerIf,
    OpVerNotIf,
    OpElse,
    OpEndIf,
    OpVerify,
    OpReturn,

    // Stack
    OpToAltStack,
    OpFromAltStack,
    Op2Drop,
    Op2Dup,
    Op3Dup,
    Op2Over,
    Op2Rot,
    Op2Swap,
    OpIfDup,
    OpDepth,
    OpDrop,
    OpDup,
    OpNip,
    OpOver,
    OpPick,
    OpRoll,
    OpRot,
    OpSwap,
    OpTuck,

    // Splice
    OpCat,
    OpSubStr,
    OpLeft,
    OpRight,
    OpSize,

    // Bitwise logic
    OpInvert,
    OpAnd,
    OpOr,
    OpXor,
    OpEqual,
    OpEqualVerify,

    // Arithmetic
    Op1Add,
    Op1Sub,
    Op2Mul,
    Op2Div,
    OpNegate,
    OpAbs,
    OpNot,
    Op0NotEqual,
    OpAdd,
    OpSub,
    OpMul,
    OpDiv,
    OpMod,
    OpLShift,
    OpRShift,
    OpBoolAnd,
    OpBoolOr,
    OpNumEqual,
    OpNumEqualVerify,
    OpNumNotEqual,
    OpLessThan,
    OpGreaterThan,
    OpLessThanOrEqual,
    OpGreaterThanOrEqual,
    OpMin,
    OpMax,
    OpWithin,

    // Crypto
    OpRipeMd160,
    OpSha1,
    OpSha256,
    OpHash160,
    OpHash256,
    OpCodeSeparator,
    OpCheckSig,
    OpCheckSigVerify,
    OpCheckMultiSig,
    OpCheckMultiSigVerify,

    // Expansion
    OpNop1,
    OpCheckLockTimeVerify,
    OpCheckSequenceVerify,
    OpNop4,
    OpNop5,
    OpNop6,
    OpNop7,
    OpNop8,
    OpNop9,
    OpNop10,

    // Tapscript
    OpCheckSigAdd,

    // Invalid/unknown
    OpInvalidOpCode,
    Unknown(u8),
}

impl Opcode {
    /// Decode an opcode from its byte value.
    pub fn from_byte(b: u8) -> Opcode {
        match b {
            0x00 => Opcode::Op0,
            0x01..=0x4b => Opcode::PushBytes(b),
            0x4c => Opcode::PushData1,
            0x4d => Opcode::PushData2,
            0x4e => Opcode::PushData4,
            0x4f => Opcode::Op1Negate,
            0x50 => Opcode::OpReserved,
            0x51..=0x60 => Opcode::OpNum(b - 0x50), // OP_1=0x51 → 1, OP_16=0x60 → 16
            0x61 => Opcode::OpNop,
            0x62 => Opcode::OpVer,
            0x63 => Opcode::OpIf,
            0x64 => Opcode::OpNotIf,
            0x65 => Opcode::OpVerIf,
            0x66 => Opcode::OpVerNotIf,
            0x67 => Opcode::OpElse,
            0x68 => Opcode::OpEndIf,
            0x69 => Opcode::OpVerify,
            0x6a => Opcode::OpReturn,
            0x6b => Opcode::OpToAltStack,
            0x6c => Opcode::OpFromAltStack,
            0x6d => Opcode::Op2Drop,
            0x6e => Opcode::Op2Dup,
            0x6f => Opcode::Op3Dup,
            0x70 => Opcode::Op2Over,
            0x71 => Opcode::Op2Rot,
            0x72 => Opcode::Op2Swap,
            0x73 => Opcode::OpIfDup,
            0x74 => Opcode::OpDepth,
            0x75 => Opcode::OpDrop,
            0x76 => Opcode::OpDup,
            0x77 => Opcode::OpNip,
            0x78 => Opcode::OpOver,
            0x79 => Opcode::OpPick,
            0x7a => Opcode::OpRoll,
            0x7b => Opcode::OpRot,
            0x7c => Opcode::OpSwap,
            0x7d => Opcode::OpTuck,
            0x7e => Opcode::OpCat,
            0x7f => Opcode::OpSubStr,
            0x80 => Opcode::OpLeft,
            0x81 => Opcode::OpRight,
            0x82 => Opcode::OpSize,
            0x83 => Opcode::OpInvert,
            0x84 => Opcode::OpAnd,
            0x85 => Opcode::OpOr,
            0x86 => Opcode::OpXor,
            0x87 => Opcode::OpEqual,
            0x88 => Opcode::OpEqualVerify,
            0x8b => Opcode::Op1Add,
            0x8c => Opcode::Op1Sub,
            0x8d => Opcode::Op2Mul,
            0x8e => Opcode::Op2Div,
            0x8f => Opcode::OpNegate,
            0x90 => Opcode::OpAbs,
            0x91 => Opcode::OpNot,
            0x92 => Opcode::Op0NotEqual,
            0x93 => Opcode::OpAdd,
            0x94 => Opcode::OpSub,
            0x95 => Opcode::OpMul,
            0x96 => Opcode::OpDiv,
            0x97 => Opcode::OpMod,
            0x98 => Opcode::OpLShift,
            0x99 => Opcode::OpRShift,
            0x9a => Opcode::OpBoolAnd,
            0x9b => Opcode::OpBoolOr,
            0x9c => Opcode::OpNumEqual,
            0x9d => Opcode::OpNumEqualVerify,
            0x9e => Opcode::OpNumNotEqual,
            0x9f => Opcode::OpLessThan,
            0xa0 => Opcode::OpGreaterThan,
            0xa1 => Opcode::OpLessThanOrEqual,
            0xa2 => Opcode::OpGreaterThanOrEqual,
            0xa3 => Opcode::OpMin,
            0xa4 => Opcode::OpMax,
            0xa5 => Opcode::OpWithin,
            0xa6 => Opcode::OpRipeMd160,
            0xa7 => Opcode::OpSha1,
            0xa8 => Opcode::OpSha256,
            0xa9 => Opcode::OpHash160,
            0xaa => Opcode::OpHash256,
            0xab => Opcode::OpCodeSeparator,
            0xac => Opcode::OpCheckSig,
            0xad => Opcode::OpCheckSigVerify,
            0xae => Opcode::OpCheckMultiSig,
            0xaf => Opcode::OpCheckMultiSigVerify,
            0xb0 => Opcode::OpNop1,
            0xb1 => Opcode::OpCheckLockTimeVerify,
            0xb2 => Opcode::OpCheckSequenceVerify,
            0xb3 => Opcode::OpNop4,
            0xb4 => Opcode::OpNop5,
            0xb5 => Opcode::OpNop6,
            0xb6 => Opcode::OpNop7,
            0xb7 => Opcode::OpNop8,
            0xb8 => Opcode::OpNop9,
            0xb9 => Opcode::OpNop10,
            0xba => Opcode::OpCheckSigAdd,
            0xff => Opcode::OpInvalidOpCode,
            _ => Opcode::Unknown(b),
        }
    }

    /// Human-readable name for the opcode.
    pub fn name(&self) -> String {
        match self {
            Opcode::Op0 => "OP_0".to_string(),
            Opcode::PushBytes(n) => format!("PUSH({})", n),
            Opcode::PushData1 => "OP_PUSHDATA1".to_string(),
            Opcode::PushData2 => "OP_PUSHDATA2".to_string(),
            Opcode::PushData4 => "OP_PUSHDATA4".to_string(),
            Opcode::Op1Negate => "OP_1NEGATE".to_string(),
            Opcode::OpReserved => "OP_RESERVED".to_string(),
            Opcode::OpNum(n) => format!("OP_{}", n),
            Opcode::OpNop => "OP_NOP".to_string(),
            Opcode::OpVer => "OP_VER".to_string(),
            Opcode::OpIf => "OP_IF".to_string(),
            Opcode::OpNotIf => "OP_NOTIF".to_string(),
            Opcode::OpVerIf => "OP_VERIF".to_string(),
            Opcode::OpVerNotIf => "OP_VERNOTIF".to_string(),
            Opcode::OpElse => "OP_ELSE".to_string(),
            Opcode::OpEndIf => "OP_ENDIF".to_string(),
            Opcode::OpVerify => "OP_VERIFY".to_string(),
            Opcode::OpReturn => "OP_RETURN".to_string(),
            Opcode::OpToAltStack => "OP_TOALTSTACK".to_string(),
            Opcode::OpFromAltStack => "OP_FROMALTSTACK".to_string(),
            Opcode::Op2Drop => "OP_2DROP".to_string(),
            Opcode::Op2Dup => "OP_2DUP".to_string(),
            Opcode::Op3Dup => "OP_3DUP".to_string(),
            Opcode::Op2Over => "OP_2OVER".to_string(),
            Opcode::Op2Rot => "OP_2ROT".to_string(),
            Opcode::Op2Swap => "OP_2SWAP".to_string(),
            Opcode::OpIfDup => "OP_IFDUP".to_string(),
            Opcode::OpDepth => "OP_DEPTH".to_string(),
            Opcode::OpDrop => "OP_DROP".to_string(),
            Opcode::OpDup => "OP_DUP".to_string(),
            Opcode::OpNip => "OP_NIP".to_string(),
            Opcode::OpOver => "OP_OVER".to_string(),
            Opcode::OpPick => "OP_PICK".to_string(),
            Opcode::OpRoll => "OP_ROLL".to_string(),
            Opcode::OpRot => "OP_ROT".to_string(),
            Opcode::OpSwap => "OP_SWAP".to_string(),
            Opcode::OpTuck => "OP_TUCK".to_string(),
            Opcode::OpCat => "OP_CAT".to_string(),
            Opcode::OpSubStr => "OP_SUBSTR".to_string(),
            Opcode::OpLeft => "OP_LEFT".to_string(),
            Opcode::OpRight => "OP_RIGHT".to_string(),
            Opcode::OpSize => "OP_SIZE".to_string(),
            Opcode::OpInvert => "OP_INVERT".to_string(),
            Opcode::OpAnd => "OP_AND".to_string(),
            Opcode::OpOr => "OP_OR".to_string(),
            Opcode::OpXor => "OP_XOR".to_string(),
            Opcode::OpEqual => "OP_EQUAL".to_string(),
            Opcode::OpEqualVerify => "OP_EQUALVERIFY".to_string(),
            Opcode::Op1Add => "OP_1ADD".to_string(),
            Opcode::Op1Sub => "OP_1SUB".to_string(),
            Opcode::Op2Mul => "OP_2MUL".to_string(),
            Opcode::Op2Div => "OP_2DIV".to_string(),
            Opcode::OpNegate => "OP_NEGATE".to_string(),
            Opcode::OpAbs => "OP_ABS".to_string(),
            Opcode::OpNot => "OP_NOT".to_string(),
            Opcode::Op0NotEqual => "OP_0NOTEQUAL".to_string(),
            Opcode::OpAdd => "OP_ADD".to_string(),
            Opcode::OpSub => "OP_SUB".to_string(),
            Opcode::OpMul => "OP_MUL".to_string(),
            Opcode::OpDiv => "OP_DIV".to_string(),
            Opcode::OpMod => "OP_MOD".to_string(),
            Opcode::OpLShift => "OP_LSHIFT".to_string(),
            Opcode::OpRShift => "OP_RSHIFT".to_string(),
            Opcode::OpBoolAnd => "OP_BOOLAND".to_string(),
            Opcode::OpBoolOr => "OP_BOOLOR".to_string(),
            Opcode::OpNumEqual => "OP_NUMEQUAL".to_string(),
            Opcode::OpNumEqualVerify => "OP_NUMEQUALVERIFY".to_string(),
            Opcode::OpNumNotEqual => "OP_NUMNOTEQUAL".to_string(),
            Opcode::OpLessThan => "OP_LESSTHAN".to_string(),
            Opcode::OpGreaterThan => "OP_GREATERTHAN".to_string(),
            Opcode::OpLessThanOrEqual => "OP_LESSTHANOREQUAL".to_string(),
            Opcode::OpGreaterThanOrEqual => "OP_GREATERTHANOREQUAL".to_string(),
            Opcode::OpMin => "OP_MIN".to_string(),
            Opcode::OpMax => "OP_MAX".to_string(),
            Opcode::OpWithin => "OP_WITHIN".to_string(),
            Opcode::OpRipeMd160 => "OP_RIPEMD160".to_string(),
            Opcode::OpSha1 => "OP_SHA1".to_string(),
            Opcode::OpSha256 => "OP_SHA256".to_string(),
            Opcode::OpHash160 => "OP_HASH160".to_string(),
            Opcode::OpHash256 => "OP_HASH256".to_string(),
            Opcode::OpCodeSeparator => "OP_CODESEPARATOR".to_string(),
            Opcode::OpCheckSig => "OP_CHECKSIG".to_string(),
            Opcode::OpCheckSigVerify => "OP_CHECKSIGVERIFY".to_string(),
            Opcode::OpCheckMultiSig => "OP_CHECKMULTISIG".to_string(),
            Opcode::OpCheckMultiSigVerify => "OP_CHECKMULTISIGVERIFY".to_string(),
            Opcode::OpNop1 => "OP_NOP1".to_string(),
            Opcode::OpCheckLockTimeVerify => "OP_CHECKLOCKTIMEVERIFY".to_string(),
            Opcode::OpCheckSequenceVerify => "OP_CHECKSEQUENCEVERIFY".to_string(),
            Opcode::OpNop4 => "OP_NOP4".to_string(),
            Opcode::OpNop5 => "OP_NOP5".to_string(),
            Opcode::OpNop6 => "OP_NOP6".to_string(),
            Opcode::OpNop7 => "OP_NOP7".to_string(),
            Opcode::OpNop8 => "OP_NOP8".to_string(),
            Opcode::OpNop9 => "OP_NOP9".to_string(),
            Opcode::OpNop10 => "OP_NOP10".to_string(),
            Opcode::OpCheckSigAdd => "OP_CHECKSIGADD".to_string(),
            Opcode::OpInvalidOpCode => "OP_INVALIDOPCODE".to_string(),
            Opcode::Unknown(b) => format!("UNKNOWN(0x{:02x})", b),
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── ScriptInstruction ──────────────────────────────────────────────────────

/// A decoded instruction from a Bitcoin script.
#[derive(Debug, Clone)]
pub struct ScriptInstruction {
    /// The opcode for this instruction.
    pub opcode: Opcode,
    /// The push data bytes (if this is a push instruction).
    pub push_data: Option<Vec<u8>>,
    /// Byte offset of this instruction within the script.
    pub byte_offset: usize,
    /// Total byte length of this instruction (opcode + any length bytes + data).
    pub byte_length: usize,
}

/// Decode a raw script byte slice into a sequence of instructions.
///
/// This mirrors Bitcoin Core's `CScript::GetOp()` logic for iterating over
/// opcodes and their push data.
pub fn decode_script(script: &[u8]) -> Vec<ScriptInstruction> {
    let mut instructions = Vec::new();
    let mut pos = 0;

    while pos < script.len() {
        let start = pos;
        let byte = script[pos];
        pos += 1;

        if byte == 0 {
            // OP_0
            instructions.push(ScriptInstruction {
                opcode: Opcode::Op0,
                push_data: Some(vec![]),
                byte_offset: start,
                byte_length: 1,
            });
        } else if byte >= 1 && byte <= 75 {
            // Direct push: next `byte` bytes
            let n = byte as usize;
            let data = if pos + n <= script.len() {
                let d = script[pos..pos + n].to_vec();
                pos += n;
                d
            } else {
                let d = script[pos..].to_vec();
                pos = script.len();
                d
            };
            instructions.push(ScriptInstruction {
                opcode: Opcode::PushBytes(byte),
                push_data: Some(data),
                byte_offset: start,
                byte_length: pos - start,
            });
        } else if byte == 0x4c {
            // OP_PUSHDATA1: next byte is length
            if pos >= script.len() {
                break;
            }
            let n = script[pos] as usize;
            pos += 1;
            let data = if pos + n <= script.len() {
                let d = script[pos..pos + n].to_vec();
                pos += n;
                d
            } else {
                let d = script[pos..].to_vec();
                pos = script.len();
                d
            };
            instructions.push(ScriptInstruction {
                opcode: Opcode::PushData1,
                push_data: Some(data),
                byte_offset: start,
                byte_length: pos - start,
            });
        } else if byte == 0x4d {
            // OP_PUSHDATA2: next 2 bytes (LE) are length
            if pos + 2 > script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[pos], script[pos + 1]]) as usize;
            pos += 2;
            let data = if pos + n <= script.len() {
                let d = script[pos..pos + n].to_vec();
                pos += n;
                d
            } else {
                let d = script[pos..].to_vec();
                pos = script.len();
                d
            };
            instructions.push(ScriptInstruction {
                opcode: Opcode::PushData2,
                push_data: Some(data),
                byte_offset: start,
                byte_length: pos - start,
            });
        } else if byte == 0x4e {
            // OP_PUSHDATA4: next 4 bytes (LE) are length
            if pos + 4 > script.len() {
                break;
            }
            let n = u32::from_le_bytes([
                script[pos],
                script[pos + 1],
                script[pos + 2],
                script[pos + 3],
            ]) as usize;
            pos += 4;
            let data = if pos + n <= script.len() {
                let d = script[pos..pos + n].to_vec();
                pos += n;
                d
            } else {
                let d = script[pos..].to_vec();
                pos = script.len();
                d
            };
            instructions.push(ScriptInstruction {
                opcode: Opcode::PushData4,
                push_data: Some(data),
                byte_offset: start,
                byte_length: pos - start,
            });
        } else {
            // Regular opcode (no push data)
            instructions.push(ScriptInstruction {
                opcode: Opcode::from_byte(byte),
                push_data: None,
                byte_offset: start,
                byte_length: 1,
            });
        }
    }

    instructions
}

// ─── StackItem ──────────────────────────────────────────────────────────────

/// Display format for stack items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackItemFormat {
    /// Hexadecimal (e.g., "0x3045022100...")
    Hex,
    /// Decimal integer (script number interpretation)
    Decimal,
    /// ASCII string (if all bytes are printable)
    Ascii,
    /// Boolean ("TRUE" / "FALSE")
    Bool,
    /// Auto-detect best format
    Auto,
}

/// A stack item (byte vector) from Bitcoin script execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackItem(pub Vec<u8>);

impl StackItem {
    /// Interpret as a Bitcoin script boolean.
    ///
    /// Empty vector and "negative zero" (0x80) are false; everything else is true.
    pub fn as_bool(&self) -> bool {
        for (i, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                if i == self.0.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Interpret as a Bitcoin script number (little-endian, sign-magnitude).
    ///
    /// Returns `None` if the byte vector is too long (> 4 bytes for standard scripts).
    pub fn as_script_num(&self) -> Option<i64> {
        if self.0.is_empty() {
            return Some(0);
        }
        if self.0.len() > 4 {
            return None;
        }

        let mut result: i64 = 0;
        for (i, &byte) in self.0.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        let last = *self.0.last().unwrap();
        if last & 0x80 != 0 {
            result &= !(0x80i64 << (8 * (self.0.len() - 1)));
            result = -result;
        }

        Some(result)
    }

    /// Format the stack item in the given format.
    pub fn format(&self, fmt: StackItemFormat) -> String {
        match fmt {
            StackItemFormat::Hex => self.format_hex(),
            StackItemFormat::Decimal => self.format_decimal(),
            StackItemFormat::Ascii => self.format_ascii(),
            StackItemFormat::Bool => self.format_bool(),
            StackItemFormat::Auto => self.format_auto(),
        }
    }

    fn format_hex(&self) -> String {
        if self.0.is_empty() {
            return "0x".to_string();
        }
        let hex: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
        format!("0x{}", hex)
    }

    fn format_decimal(&self) -> String {
        match self.as_script_num() {
            Some(n) => n.to_string(),
            None => self.format_hex(),
        }
    }

    fn format_ascii(&self) -> String {
        if self.0.iter().all(|&b| b >= 0x20 && b <= 0x7e) && !self.0.is_empty() {
            String::from_utf8_lossy(&self.0).to_string()
        } else {
            self.format_hex()
        }
    }

    fn format_bool(&self) -> String {
        if self.as_bool() {
            "TRUE".to_string()
        } else {
            "FALSE".to_string()
        }
    }

    fn format_auto(&self) -> String {
        if self.0.is_empty() {
            return "0x".to_string();
        }
        if self.0.len() == 1 && self.0[0] == 0x01 {
            return "TRUE".to_string();
        }
        if self.0.len() <= 2 {
            if let Some(n) = self.as_script_num() {
                return n.to_string();
            }
        }
        self.format_hex()
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the stack item is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for StackItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format(StackItemFormat::Auto))
    }
}

// ─── ScriptPhase ────────────────────────────────────────────────────────────

/// The execution phase of a Bitcoin script.
///
/// During verification, multiple scripts may be executed in sequence.
/// The phase is inferred by detecting changes in `script_bytes` across steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptPhase {
    /// The scriptSig (unlocking script) from the transaction input.
    ScriptSig,
    /// The scriptPubKey (locking script) from the previous output.
    ScriptPubKey,
    /// The redeem script (for P2SH transactions).
    RedeemScript,
    /// The witness script (for P2WSH transactions).
    WitnessScript,
    /// Phase could not be determined.
    Unknown,
}

impl fmt::Display for ScriptPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptPhase::ScriptSig => write!(f, "ScriptSig"),
            ScriptPhase::ScriptPubKey => write!(f, "ScriptPubKey"),
            ScriptPhase::RedeemScript => write!(f, "RedeemScript"),
            ScriptPhase::WitnessScript => write!(f, "WitnessScript"),
            ScriptPhase::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_p2pkh_script() {
        // OP_DUP OP_HASH160 PUSH(20) <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script = hex_decode("76a914") // OP_DUP OP_HASH160 PUSH(20)
            .into_iter()
            .chain(vec![0xab; 20]) // 20-byte hash
            .chain(hex_decode("88ac")) // OP_EQUALVERIFY OP_CHECKSIG
            .collect::<Vec<u8>>();

        let instructions = decode_script(&script);
        assert_eq!(instructions.len(), 5);

        assert_eq!(instructions[0].opcode, Opcode::OpDup);
        assert_eq!(instructions[0].push_data, None);

        assert_eq!(instructions[1].opcode, Opcode::OpHash160);

        assert_eq!(instructions[2].opcode, Opcode::PushBytes(20));
        assert_eq!(instructions[2].push_data.as_ref().unwrap().len(), 20);

        assert_eq!(instructions[3].opcode, Opcode::OpEqualVerify);
        assert_eq!(instructions[4].opcode, Opcode::OpCheckSig);
    }

    #[test]
    fn test_decode_pushdata_variants() {
        // OP_PUSHDATA1 with 100 bytes of data
        let mut script = vec![0x4c, 100];
        script.extend(vec![0xaa; 100]);

        let instructions = decode_script(&script);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, Opcode::PushData1);
        assert_eq!(instructions[0].push_data.as_ref().unwrap().len(), 100);

        // OP_PUSHDATA2 with 256 bytes of data
        let mut script2 = vec![0x4d, 0x00, 0x01];
        script2.extend(vec![0xbb; 256]);

        let instructions2 = decode_script(&script2);
        assert_eq!(instructions2.len(), 1);
        assert_eq!(instructions2[0].opcode, Opcode::PushData2);
        assert_eq!(instructions2[0].push_data.as_ref().unwrap().len(), 256);
    }

    #[test]
    fn test_opcode_names() {
        assert_eq!(Opcode::Op0.name(), "OP_0");
        assert_eq!(Opcode::OpDup.name(), "OP_DUP");
        assert_eq!(Opcode::OpHash160.name(), "OP_HASH160");
        assert_eq!(Opcode::OpCheckSig.name(), "OP_CHECKSIG");
        assert_eq!(Opcode::PushBytes(33).name(), "PUSH(33)");
        assert_eq!(Opcode::OpNum(1).name(), "OP_1");
        assert_eq!(Opcode::OpNum(16).name(), "OP_16");
        assert_eq!(Opcode::OpCheckLockTimeVerify.name(), "OP_CHECKLOCKTIMEVERIFY");
        assert_eq!(Opcode::Unknown(0xfe).name(), "UNKNOWN(0xfe)");
    }

    #[test]
    fn test_stack_item_bool() {
        assert!(!StackItem(vec![]).as_bool());
        assert!(!StackItem(vec![0x00]).as_bool());
        assert!(!StackItem(vec![0x00, 0x00]).as_bool());
        assert!(!StackItem(vec![0x80]).as_bool());
        assert!(!StackItem(vec![0x00, 0x80]).as_bool());
        assert!(StackItem(vec![0x01]).as_bool());
        assert!(StackItem(vec![0x42]).as_bool());
        assert!(StackItem(vec![0x80, 0x00]).as_bool());
    }

    #[test]
    fn test_stack_item_script_num() {
        assert_eq!(StackItem(vec![]).as_script_num(), Some(0));
        assert_eq!(StackItem(vec![0x01]).as_script_num(), Some(1));
        assert_eq!(StackItem(vec![0x7f]).as_script_num(), Some(127));
        assert_eq!(StackItem(vec![0x80, 0x00]).as_script_num(), Some(128));
        assert_eq!(StackItem(vec![0xff, 0x00]).as_script_num(), Some(255));
        assert_eq!(StackItem(vec![0x81]).as_script_num(), Some(-1));
        assert_eq!(StackItem(vec![0xff]).as_script_num(), Some(-127));
        assert_eq!(StackItem(vec![0x80, 0x80]).as_script_num(), Some(-128));
        assert_eq!(StackItem(vec![0x01, 0x02, 0x03, 0x04, 0x05]).as_script_num(), None);
    }

    #[test]
    fn test_stack_item_format() {
        assert_eq!(StackItem(vec![0xab, 0xcd]).format(StackItemFormat::Hex), "0xabcd");
        assert_eq!(StackItem(vec![]).format(StackItemFormat::Hex), "0x");
        assert_eq!(StackItem(vec![0x01]).format(StackItemFormat::Bool), "TRUE");
        assert_eq!(StackItem(vec![]).format(StackItemFormat::Bool), "FALSE");
        assert_eq!(StackItem(vec![0x01]).format(StackItemFormat::Auto), "TRUE");
        assert_eq!(StackItem(vec![]).format(StackItemFormat::Auto), "0x");
        assert_eq!(StackItem(b"hello".to_vec()).format(StackItemFormat::Ascii), "hello");
        assert_eq!(StackItem(vec![0x00, 0x01]).format(StackItemFormat::Ascii), "0x0001");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
