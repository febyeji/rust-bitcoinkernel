//! Bitcoin script debugger: types and execution tracing.
//!
//! This module provides:
//!
//! - Pure data types for script execution state: [`Opcode`], [`ScriptInstruction`],
//!   [`StackItem`], [`ScriptPhase`], [`ScriptStep`], [`ScriptTrace`].
//! - [`ScriptDebugger`]: registers a global C callback into libbitcoinkernel's
//!   `EvalScript` loop and collects execution steps.
//! - [`trace_verify`]: convenience wrapper that runs [`verify`] under a debugger
//!   and returns the full execution trace.
//!
//! # Thread safety
//!
//! libbitcoinkernel's script debug callback is a process-global singleton.
//! Only one [`ScriptDebugger`] may be active at a time; attempting to create
//! a second one while the first is alive will panic.  The debugger is
//! automatically unregistered when it is dropped.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use libbitcoinkernel_sys::{
    btck_get_last_script_error, btck_register_script_debug_callback,
    btck_unregister_script_debug_callback,
};

use crate::core::verify::PrecomputedTransactionData;
use crate::{verify, KernelError, ScriptPubkeyExt, TransactionExt};

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

// ─── ScriptExecError ─────────────────────────────────────────────────────────

/// Detailed script execution error, mirroring Bitcoin Core's `ScriptError` enum.
///
/// Populated in [`ScriptTrace::script_error`] when verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptExecError {
    /// No error (verification passed).
    Ok,
    UnknownError,
    /// The top-of-stack value was false after script execution.
    EvalFalse,
    /// OP_RETURN was executed.
    OpReturn,
    // Size limits
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultiSigVerify,
    CheckSigVerify,
    NumEqualVerify,
    // Logical/format/canonical errors
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    // CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY
    NegativeLocktime,
    UnsatisfiedLocktime,
    // Malleability
    SigHashType,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    SigNullFail,
    // Softfork safeness
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,
    // Segwit
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2SH,
    WitnessUnexpected,
    WitnessPubkeyType,
    // Taproot
    SchnorrSigSize,
    SchnorrSigHashType,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultiSig,
    TapscriptMinimalIf,
    TapscriptEmptyPubkey,
    // Misc
    OpCodeSeparator,
    SigFindAndDelete,
    /// An error code not recognised by this version of the library.
    Other(u32),
}

impl ScriptExecError {
    pub(crate) fn from_raw(v: u32) -> Self {
        // Values mirror Bitcoin Core's ScriptError enum in script/script_error.h.
        // The numeric values are stable — they are part of the ABI defined in
        // bitcoinkernel.h via BTCK_SCRIPT_ERR_* #define constants.
        match v {
            0 => ScriptExecError::Ok,
            1 => ScriptExecError::UnknownError,
            2 => ScriptExecError::EvalFalse,
            3 => ScriptExecError::OpReturn,
            4 => ScriptExecError::ScriptSize,
            5 => ScriptExecError::PushSize,
            6 => ScriptExecError::OpCount,
            7 => ScriptExecError::StackSize,
            8 => ScriptExecError::SigCount,
            9 => ScriptExecError::PubkeyCount,
            10 => ScriptExecError::Verify,
            11 => ScriptExecError::EqualVerify,
            12 => ScriptExecError::CheckMultiSigVerify,
            13 => ScriptExecError::CheckSigVerify,
            14 => ScriptExecError::NumEqualVerify,
            15 => ScriptExecError::BadOpcode,
            16 => ScriptExecError::DisabledOpcode,
            17 => ScriptExecError::InvalidStackOperation,
            18 => ScriptExecError::InvalidAltstackOperation,
            19 => ScriptExecError::UnbalancedConditional,
            20 => ScriptExecError::NegativeLocktime,
            21 => ScriptExecError::UnsatisfiedLocktime,
            22 => ScriptExecError::SigHashType,
            23 => ScriptExecError::SigDer,
            24 => ScriptExecError::MinimalData,
            25 => ScriptExecError::SigPushOnly,
            26 => ScriptExecError::SigHighS,
            27 => ScriptExecError::SigNullDummy,
            28 => ScriptExecError::PubkeyType,
            29 => ScriptExecError::CleanStack,
            30 => ScriptExecError::MinimalIf,
            31 => ScriptExecError::SigNullFail,
            32 => ScriptExecError::DiscourageUpgradableNops,
            33 => ScriptExecError::DiscourageUpgradableWitnessProgram,
            34 => ScriptExecError::DiscourageUpgradableTaprootVersion,
            35 => ScriptExecError::DiscourageOpSuccess,
            36 => ScriptExecError::DiscourageUpgradablePubkeyType,
            37 => ScriptExecError::WitnessProgramWrongLength,
            38 => ScriptExecError::WitnessProgramWitnessEmpty,
            39 => ScriptExecError::WitnessProgramMismatch,
            40 => ScriptExecError::WitnessMalleated,
            41 => ScriptExecError::WitnessMalleatedP2SH,
            42 => ScriptExecError::WitnessUnexpected,
            43 => ScriptExecError::WitnessPubkeyType,
            44 => ScriptExecError::SchnorrSigSize,
            45 => ScriptExecError::SchnorrSigHashType,
            46 => ScriptExecError::SchnorrSig,
            47 => ScriptExecError::TaprootWrongControlSize,
            48 => ScriptExecError::TapscriptValidationWeight,
            49 => ScriptExecError::TapscriptCheckMultiSig,
            50 => ScriptExecError::TapscriptMinimalIf,
            51 => ScriptExecError::TapscriptEmptyPubkey,
            52 => ScriptExecError::OpCodeSeparator,
            53 => ScriptExecError::SigFindAndDelete,
            other => ScriptExecError::Other(other),
        }
    }

    /// Human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            ScriptExecError::Ok => "OK",
            ScriptExecError::UnknownError => "unknown error",
            ScriptExecError::EvalFalse => "script evaluated to false",
            ScriptExecError::OpReturn => "OP_RETURN executed",
            ScriptExecError::ScriptSize => "script too large",
            ScriptExecError::PushSize => "push data too large",
            ScriptExecError::OpCount => "too many opcodes",
            ScriptExecError::StackSize => "stack too large",
            ScriptExecError::SigCount => "too many signatures",
            ScriptExecError::PubkeyCount => "too many public keys",
            ScriptExecError::Verify => "OP_VERIFY failed",
            ScriptExecError::EqualVerify => "OP_EQUALVERIFY failed",
            ScriptExecError::CheckMultiSigVerify => "OP_CHECKMULTISIGVERIFY failed",
            ScriptExecError::CheckSigVerify => "OP_CHECKSIGVERIFY failed",
            ScriptExecError::NumEqualVerify => "OP_NUMEQUALVERIFY failed",
            ScriptExecError::BadOpcode => "invalid opcode",
            ScriptExecError::DisabledOpcode => "disabled opcode",
            ScriptExecError::InvalidStackOperation => "invalid stack operation",
            ScriptExecError::InvalidAltstackOperation => "invalid altstack operation",
            ScriptExecError::UnbalancedConditional => "unbalanced conditional",
            ScriptExecError::NegativeLocktime => "negative locktime",
            ScriptExecError::UnsatisfiedLocktime => "locktime not satisfied",
            ScriptExecError::SigHashType => "invalid signature hash type",
            ScriptExecError::SigDer => "non-DER signature",
            ScriptExecError::MinimalData => "non-minimal data encoding",
            ScriptExecError::SigPushOnly => "signature in non-push scriptSig",
            ScriptExecError::SigHighS => "non-low-S signature",
            ScriptExecError::SigNullDummy => "extra items left on stack after multisig",
            ScriptExecError::PubkeyType => "invalid public key type",
            ScriptExecError::CleanStack => "extra items left on stack",
            ScriptExecError::MinimalIf => "OP_IF argument not minimal",
            ScriptExecError::SigNullFail => "non-null signature after failed CHECKSIG",
            ScriptExecError::DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            ScriptExecError::DiscourageUpgradableWitnessProgram => {
                "witness version reserved for soft-fork upgrades"
            }
            ScriptExecError::DiscourageUpgradableTaprootVersion => {
                "taproot version reserved for soft-fork upgrades"
            }
            ScriptExecError::DiscourageOpSuccess => "OP_SUCCESSx reserved for soft-fork upgrades",
            ScriptExecError::DiscourageUpgradablePubkeyType => {
                "public key type reserved for soft-fork upgrades"
            }
            ScriptExecError::WitnessProgramWrongLength => "witness program wrong length",
            ScriptExecError::WitnessProgramWitnessEmpty => "witness program with empty witness",
            ScriptExecError::WitnessProgramMismatch => "witness program mismatch",
            ScriptExecError::WitnessMalleated => "witness requires empty scriptSig",
            ScriptExecError::WitnessMalleatedP2SH => {
                "witness requires only-redeemscript scriptSig"
            }
            ScriptExecError::WitnessUnexpected => "witness provided for non-witness script",
            ScriptExecError::WitnessPubkeyType => "non-compressed public key in segwit",
            ScriptExecError::SchnorrSigSize => "invalid Schnorr signature size",
            ScriptExecError::SchnorrSigHashType => "invalid Schnorr signature hash type",
            ScriptExecError::SchnorrSig => "invalid Schnorr signature",
            ScriptExecError::TaprootWrongControlSize => "invalid taproot control block size",
            ScriptExecError::TapscriptValidationWeight => "tapscript validation weight exceeded",
            ScriptExecError::TapscriptCheckMultiSig => {
                "OP_CHECKMULTISIG(VERIFY) not available in tapscript"
            }
            ScriptExecError::TapscriptMinimalIf => "OP_IF/NOTIF argument must be minimal in tapscript",
            ScriptExecError::TapscriptEmptyPubkey => "empty public key in tapscript",
            ScriptExecError::OpCodeSeparator => "OP_CODESEPARATOR in non-segwit script",
            ScriptExecError::SigFindAndDelete => "FindAndDelete is not available in segwit",
            ScriptExecError::Other(_) => "unrecognised script error",
        }
    }
}

impl fmt::Display for ScriptExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
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

// ─── ScriptStep ─────────────────────────────────────────────────────────────

/// A single step of Bitcoin script execution.
///
/// Represents the state of the interpreter *before* the opcode at `opcode_pos`
/// executes (or the final state after the last opcode when `instruction` is
/// `None`).
#[derive(Debug, Clone)]
pub struct ScriptStep {
    /// Global step index across all phases (0-based).
    pub step_index: usize,
    /// The decoded instruction about to execute, or `None` for the final state.
    pub instruction: Option<ScriptInstruction>,
    /// The main stack at this point.
    pub stack: Vec<StackItem>,
    /// The alt stack at this point.
    pub altstack: Vec<StackItem>,
    /// Raw script bytes for this phase.
    pub script_bytes: Vec<u8>,
    /// The inferred execution phase.
    pub phase: ScriptPhase,
    /// The C-side opcode iteration counter.
    pub opcode_pos: u32,
    /// Whether execution is active (`true`) or inside a non-taken `OP_IF` branch.
    pub f_exec: bool,
}

// ─── ScriptTrace ─────────────────────────────────────────────────────────────

/// Complete execution trace for a Bitcoin script verification.
///
/// Returned by [`trace_verify`].
#[derive(Debug, Clone)]
pub struct ScriptTrace {
    /// All execution steps in order.
    pub steps: Vec<ScriptStep>,
    /// Whether verification succeeded.
    pub success: bool,
    /// High-level error description if verification failed.
    pub error: Option<String>,
    /// Detailed script execution error code, if verification failed.
    ///
    /// This mirrors Bitcoin Core's internal `ScriptError` enum and tells you
    /// exactly which check failed (e.g. [`ScriptExecError::EqualVerify`],
    /// [`ScriptExecError::CheckSigVerify`], etc.).
    pub script_error: Option<ScriptExecError>,
}

impl ScriptTrace {
    /// Number of steps in the trace.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns true if the trace has no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Get a step by index.
    pub fn step(&self, idx: usize) -> Option<&ScriptStep> {
        self.steps.get(idx)
    }

    /// Iterate over all steps.
    pub fn iter(&self) -> std::slice::Iter<'_, ScriptStep> {
        self.steps.iter()
    }

    /// Collect the distinct phases present in the trace, in order.
    pub fn phases(&self) -> Vec<ScriptPhase> {
        let mut seen = Vec::new();
        for step in &self.steps {
            if seen.last() != Some(&step.phase) {
                seen.push(step.phase);
            }
        }
        seen
    }

    /// Return the final stack (from the last step), if any.
    pub fn final_stack(&self) -> Option<&Vec<StackItem>> {
        self.steps.last().map(|s| &s.stack)
    }
}

// ─── FFI Internals ──────────────────────────────────────────────────────────

/// Guard to ensure only one ScriptDebugger is active at a time.
static DEBUGGER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Raw step data as received from the C callback; converted to [`ScriptStep`]
/// in [`build_trace`] after all steps are collected.
struct RawStepData {
    stack: Vec<Vec<u8>>,
    altstack: Vec<Vec<u8>>,
    script_bytes: Vec<u8>,
    opcode_pos: u32,
    f_exec: bool,
}

/// Heap-allocated holder passed as `user_data` to the C callback.
struct CallbackHolder {
    raw_steps: Vec<RawStepData>,
}

/// Copy a flat C array of byte slices into an owned `Vec<Vec<u8>>`.
///
/// # Safety
///
/// `items` and `sizes` must each point to `count` valid, aligned values.
/// Each `items[i]` must be valid for `sizes[i]` bytes.
unsafe fn collect_stack(
    items: *const *const std::os::raw::c_uchar,
    sizes: *const usize,
    count: usize,
) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let ptr = *items.add(i);
            let len = *sizes.add(i);
            if len == 0 {
                vec![]
            } else {
                std::slice::from_raw_parts(ptr, len).to_vec()
            }
        })
        .collect()
}

/// C-callable trampoline that forwards to `CallbackHolder`.
///
/// # Safety
///
/// `user_data` must point to a valid `CallbackHolder` for the duration
/// the callback is registered. `state` must point to a valid
/// `btck_ScriptDebugState`.
unsafe extern "C" fn script_debug_callback_trampoline(
    user_data: *mut std::os::raw::c_void,
    state: *const libbitcoinkernel_sys::btck_ScriptDebugState,
) {
    let holder = &mut *(user_data as *mut CallbackHolder);
    let s = &*state;

    let stack = collect_stack(s.stack_items, s.stack_item_sizes, s.stack_size);
    let altstack = collect_stack(s.altstack_items, s.altstack_item_sizes, s.altstack_size);
    let script_bytes = std::slice::from_raw_parts(s.script, s.script_size).to_vec();

    holder.raw_steps.push(RawStepData {
        stack,
        altstack,
        script_bytes,
        opcode_pos: s.opcode_pos,
        f_exec: s.f_exec != 0,
    });
}

/// Convert raw callback data into a [`ScriptTrace`] with phase detection.
///
/// Phase is inferred by watching `script_bytes` change between steps:
/// first script = ScriptSig, second = ScriptPubKey, third = RedeemScript,
/// fourth = WitnessScript.
fn build_trace(
    raw: Vec<RawStepData>,
    result: Result<(), KernelError>,
    exec_error: ScriptExecError,
) -> ScriptTrace {
    let mut steps = Vec::with_capacity(raw.len());
    let mut phase_order: Vec<Vec<u8>> = Vec::new();

    for (global_idx, raw_step) in raw.into_iter().enumerate() {
        // Detect phase by unique script_bytes sequence
        let phase_idx = if let Some(existing) = phase_order
            .iter()
            .position(|s| *s == raw_step.script_bytes)
        {
            existing
        } else {
            phase_order.push(raw_step.script_bytes.clone());
            phase_order.len() - 1
        };

        let phase = match phase_idx {
            0 => ScriptPhase::ScriptSig,
            1 => ScriptPhase::ScriptPubKey,
            2 => ScriptPhase::RedeemScript,
            3 => ScriptPhase::WitnessScript,
            _ => ScriptPhase::Unknown,
        };

        let instructions = decode_script(&raw_step.script_bytes);
        let instruction = instructions.get(raw_step.opcode_pos as usize).cloned();

        let stack = raw_step
            .stack
            .into_iter()
            .map(StackItem)
            .collect();
        let altstack = raw_step
            .altstack
            .into_iter()
            .map(StackItem)
            .collect();

        steps.push(ScriptStep {
            step_index: global_idx,
            instruction,
            stack,
            altstack,
            script_bytes: raw_step.script_bytes,
            phase,
            opcode_pos: raw_step.opcode_pos,
            f_exec: raw_step.f_exec,
        });
    }

    let (success, error, script_error) = match result {
        Ok(()) => (true, None, None),
        Err(e) => {
            let se = if exec_error == ScriptExecError::Ok {
                None
            } else {
                Some(exec_error)
            };
            (false, Some(e.to_string()), se)
        }
    };

    ScriptTrace {
        steps,
        success,
        error,
        script_error,
    }
}

// ─── ScriptDebugger ──────────────────────────────────────────────────────────

/// Registers a script debug callback into libbitcoinkernel's `EvalScript` loop.
///
/// While a `ScriptDebugger` is alive, every opcode iteration during any
/// `verify` call will invoke the callback and accumulate steps.
/// The callback is unregistered when the debugger is dropped.
///
/// Only one `ScriptDebugger` may exist at a time; creating a second will panic.
pub struct ScriptDebugger {
    holder: *mut CallbackHolder,
}

impl ScriptDebugger {
    /// Create a new debugger and register the global C callback.
    ///
    /// # Panics
    ///
    /// Panics if another `ScriptDebugger` is already active.
    pub fn new() -> Self {
        if DEBUGGER_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            panic!(
                "A ScriptDebugger is already active. \
                 Only one debugger can be registered at a time."
            );
        }

        let holder = Box::into_raw(Box::new(CallbackHolder {
            raw_steps: Vec::new(),
        }));

        unsafe {
            btck_register_script_debug_callback(
                holder as *mut _,
                Some(script_debug_callback_trampoline),
            );
        }

        ScriptDebugger { holder }
    }

    /// Consume the debugger and return the accumulated raw steps.
    ///
    /// The callback is unregistered before the steps are returned.
    fn into_raw_steps(mut self) -> Vec<RawStepData> {
        unsafe {
            btck_unregister_script_debug_callback();
            let holder = Box::from_raw(self.holder);
            self.holder = std::ptr::null_mut();
            DEBUGGER_ACTIVE.store(false, Ordering::SeqCst);
            // Prevent Drop from running again
            std::mem::forget(self);
            holder.raw_steps
        }
    }
}

impl Drop for ScriptDebugger {
    fn drop(&mut self) {
        if !self.holder.is_null() {
            unsafe {
                btck_unregister_script_debug_callback();
                let _ = Box::from_raw(self.holder);
                self.holder = std::ptr::null_mut();
            }
            DEBUGGER_ACTIVE.store(false, Ordering::SeqCst);
        }
    }
}

// SAFETY: The holder pointer is only accessed from the thread that owns
// the ScriptDebugger (before verify()) and from the C callback (which is
// called synchronously during verify() on the same thread).
unsafe impl Send for ScriptDebugger {}

// ─── trace_verify ────────────────────────────────────────────────────────────

/// Run script verification and collect a full execution trace.
///
/// This is a convenience wrapper around [`verify`] that installs a
/// [`ScriptDebugger`], runs verification, and returns a [`ScriptTrace`]
/// with step-by-step execution data and the verification result.
///
/// # Panics
///
/// Panics if another [`ScriptDebugger`] is already active.
pub fn trace_verify(
    script_pubkey: &impl ScriptPubkeyExt,
    amount: Option<i64>,
    tx_to: &impl TransactionExt,
    input_index: usize,
    flags: Option<u32>,
    precomputed_txdata: &PrecomputedTransactionData,
) -> ScriptTrace {
    let debugger = ScriptDebugger::new();
    let result = verify(
        script_pubkey,
        amount,
        tx_to,
        input_index,
        flags,
        precomputed_txdata,
    );
    let raw = debugger.into_raw_steps();
    let exec_error = ScriptExecError::from_raw(unsafe { btck_get_last_script_error() });
    build_trace(raw, result, exec_error)
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

    #[test]
    fn test_phase_inference() {
        // build_trace with two distinct script_bytes sequences → ScriptSig then ScriptPubKey
        let script_sig = vec![0x00u8]; // OP_0
        let script_pubkey = vec![0x51u8]; // OP_1

        let raw = vec![
            RawStepData {
                stack: vec![],
                altstack: vec![],
                script_bytes: script_sig.clone(),
                opcode_pos: 0,
                f_exec: true,
            },
            RawStepData {
                stack: vec![vec![]],
                altstack: vec![],
                script_bytes: script_pubkey.clone(),
                opcode_pos: 0,
                f_exec: true,
            },
        ];

        let trace = build_trace(raw, Ok(()), ScriptExecError::Ok);
        assert_eq!(trace.steps[0].phase, ScriptPhase::ScriptSig);
        assert_eq!(trace.steps[1].phase, ScriptPhase::ScriptPubKey);
        assert!(trace.success);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
