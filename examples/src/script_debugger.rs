use std::collections::HashSet;

use bitcoin::Script;
use bitcoinkernel::{
    prelude::*, PrecomputedTransactionData, ScriptDebugFrame, ScriptPubkey, ScriptTrace,
    SigVersion, Transaction, TxOut, VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH,
    VERIFY_TAPROOT, VERIFY_WITNESS,
};
struct Session {
    script_pubkey: Option<Vec<u8>>,
    spending_tx_bytes: Option<Vec<u8>>,
    amount: i64,
    input_index: usize,
    flags: u32,
    bare_script: Option<Vec<u8>>,
    initial_stack: Vec<Vec<u8>>,
    trace: Option<ScriptTrace>,
    cursor: usize,
    breakpoints: HashSet<usize>,
}

impl Session {
    fn new() -> Self {
        Session {
            script_pubkey: None,
            spending_tx_bytes: None,
            amount: 0,
            input_index: 0,
            flags: VERIFY_ALL,
            bare_script: None,
            initial_stack: Vec::new(),
            trace: None,
            cursor: 0,
            breakpoints: HashSet::new(),
        }
    }

    fn handle_command(&mut self, line: &str) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "load" => {
                if parts.len() < 3 {
                    println!("Usage: load tx <hex> | load script <hex>");
                    return;
                }
                match parts[1] {
                    "tx" => self.cmd_load_tx(parts[2]),
                    "script" => self.cmd_load_script(parts[2]),
                    _ => println!(
                        "Unknown load target '{}'. Use: load tx <hex> | load script <hex>",
                        parts[1]
                    ),
                }
            }
            "set" => {
                if parts.len() < 3 {
                    println!("Usage: set scriptpubkey|spk|amount|flags|input <value>");
                    return;
                }
                match parts[1] {
                    "scriptpubkey" | "spk" => self.cmd_set_scriptpubkey(parts[2]),
                    "amount" => self.cmd_set_amount(parts[2]),
                    "flags" => self.cmd_set_flags(parts[2]),
                    "input" => self.cmd_set_input(parts[2]),
                    _ => println!(
                        "Unknown set field '{}'. Use: scriptpubkey|spk|amount|flags|input",
                        parts[1]
                    ),
                }
            }
            "stack" => {
                if parts.len() < 2 {
                    println!("Usage: stack push <hex> | stack clear");
                    return;
                }
                match parts[1] {
                    "push" => {
                        if parts.len() < 3 {
                            println!("Usage: stack push <hex>");
                            return;
                        }
                        self.cmd_stack_push(parts[2]);
                    }
                    "clear" => {
                        self.initial_stack.clear();
                        println!("Initial stack cleared.");
                    }
                    _ => println!(
                        "Unknown stack command '{}'. Use: stack push <hex> | stack clear",
                        parts[1]
                    ),
                }
            }
            "run" => self.cmd_run(),
            "step" | "s" => self.cmd_step(),
            "back" | "b" => self.cmd_back(),
            "goto" => {
                if parts.len() < 2 {
                    println!("Usage: goto <step>");
                    return;
                }
                self.cmd_goto(parts[1]);
            }
            "continue" | "c" => self.cmd_continue(),
            "break" => {
                if parts.len() < 2 {
                    println!("Usage: break <step> | break clear");
                    return;
                }
                match parts[1] {
                    "clear" => {
                        self.breakpoints.clear();
                        println!("All breakpoints cleared.");
                    }
                    n => self.cmd_break(n),
                }
            }
            "print" => {
                if parts.len() < 2 {
                    println!("Usage: print stack|script|frame");
                    return;
                }
                match parts[1] {
                    "stack" => self.cmd_print_stack(),
                    "script" => self.cmd_print_script(),
                    "frame" => self.cmd_print_frame(),
                    _ => println!(
                        "Unknown print target '{}'. Use: print stack|script|frame",
                        parts[1]
                    ),
                }
            }
            "ps" => self.cmd_print_stack(),
            "psc" => self.cmd_print_script(),
            "p" => self.cmd_print_frame(),
            "info" | "i" => self.cmd_info(),
            "reset" => {
                *self = Session::new();
                println!("Session reset.");
            }
            "help" | "h" => Self::cmd_help(),
            _ => println!(
                "Unknown command '{}'. Type 'help' for available commands.",
                parts[0]
            ),
        }
    }

    fn cmd_load_tx(&mut self, hex_str: &str) {
        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                println!("Invalid hex: {}", e);
                return;
            }
        };
        let tx = match Transaction::new(&bytes) {
            Ok(t) => t,
            Err(e) => {
                println!("Failed to parse transaction: {}", e);
                return;
            }
        };
        let n_inputs = tx.inputs().count();
        let n_outputs = tx.outputs().count();
        self.spending_tx_bytes = Some(bytes);
        self.bare_script = None;
        self.initial_stack.clear();
        self.trace = None;
        self.cursor = 0;
        println!(
            "Transaction loaded: {} input(s), {} output(s).",
            n_inputs, n_outputs
        );
    }

    fn cmd_load_script(&mut self, hex_str: &str) {
        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                println!("Invalid hex: {}", e);
                return;
            }
        };
        let len = bytes.len();
        self.bare_script = Some(bytes);
        self.script_pubkey = None;
        self.spending_tx_bytes = None;
        self.trace = None;
        self.cursor = 0;
        println!("Bare script loaded: {} byte(s).", len);
    }

    fn cmd_set_scriptpubkey(&mut self, hex_str: &str) {
        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                println!("Invalid hex: {}", e);
                return;
            }
        };
        let len = bytes.len();
        self.script_pubkey = Some(bytes);
        if self.trace.is_some() {
            self.trace = None;
            self.cursor = 0;
            println!("Trace cleared \u{2014} run again to capture a new trace.");
        }
        println!("scriptPubKey set ({} bytes).", len);
    }

    fn cmd_set_amount(&mut self, val: &str) {
        match val.parse::<i64>() {
            Ok(n) => {
                self.amount = n;
                if self.trace.is_some() {
                    self.trace = None;
                    self.cursor = 0;
                    println!("Trace cleared \u{2014} run again to capture a new trace.");
                }
                println!("Amount set to {}.", n);
            }
            Err(_) => println!("Invalid integer: {}", val),
        }
    }

    fn cmd_set_flags(&mut self, val: &str) {
        let mut flags = 0u32;
        for name in val.split('|') {
            match name.trim() {
                "NONE" => flags |= VERIFY_NONE,
                "ALL" => flags |= VERIFY_ALL,
                "ALL_PRE_TAPROOT" => flags |= VERIFY_ALL_PRE_TAPROOT,
                "P2SH" => flags |= VERIFY_P2SH,
                "DERSIG" => flags |= VERIFY_DERSIG,
                "NULLDUMMY" => flags |= VERIFY_NULLDUMMY,
                "CHECKLOCKTIMEVERIFY" => flags |= VERIFY_CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => flags |= VERIFY_CHECKSEQUENCEVERIFY,
                "WITNESS" => flags |= VERIFY_WITNESS,
                "TAPROOT" => flags |= VERIFY_TAPROOT,
                other => {
                    println!("Unknown flag '{}'. Valid: NONE, ALL, ALL_PRE_TAPROOT, P2SH, DERSIG, NULLDUMMY, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, TAPROOT", other);
                    return;
                }
            }
        }
        self.flags = flags;
        if self.trace.is_some() {
            self.trace = None;
            self.cursor = 0;
            println!("Trace cleared \u{2014} run again to capture a new trace.");
        }
        println!("Flags set to 0x{:08x}.", flags);
    }

    fn cmd_set_input(&mut self, val: &str) {
        match val.parse::<usize>() {
            Ok(n) => {
                self.input_index = n;
                if self.trace.is_some() {
                    self.trace = None;
                    self.cursor = 0;
                    println!("Trace cleared \u{2014} run again to capture a new trace.");
                }
                println!("Input index set to {}.", n);
            }
            Err(_) => println!("Invalid integer: {}", val),
        }
    }

    fn cmd_stack_push(&mut self, hex_str: &str) {
        match hex::decode(hex_str) {
            Ok(bytes) => {
                let len = bytes.len();
                self.initial_stack.push(bytes);
                println!(
                    "Pushed {} byte(s) onto initial stack (depth now {}).",
                    len,
                    self.initial_stack.len()
                );
            }
            Err(e) => println!("Invalid hex: {}", e),
        }
    }

    fn cmd_run(&mut self) {
        if let Some(ref script) = self.bare_script {
            let script = script.clone();
            match ScriptTrace::from_script(&script, &self.initial_stack) {
                Ok(trace) => {
                    let len = trace.len();
                    if let Some(err) = trace.error() {
                        println!("Script error: {}", err);
                    }
                    println!("Trace captured: {} step(s).", len);
                    self.trace = Some(trace);
                    self.cursor = 0;
                    if len > 0 {
                        self.print_current_frame();
                    }
                }
                Err(e) => println!("Run failed: {}", e),
            }
        } else if self.spending_tx_bytes.is_some() && self.script_pubkey.is_some() {
            let tx_bytes = self.spending_tx_bytes.as_ref().unwrap();
            let spk_bytes = self.script_pubkey.as_ref().unwrap();

            if self.flags & VERIFY_TAPROOT != 0 {
                println!("Warning: taproot verification requires spent outputs, which are not yet supported.");
                println!("Sighash computation may be incorrect for taproot inputs.");
            }

            let tx = match Transaction::new(tx_bytes) {
                Ok(t) => t,
                Err(e) => {
                    println!("Failed to parse transaction: {}", e);
                    return;
                }
            };
            let spk = match ScriptPubkey::try_from(spk_bytes.as_slice()) {
                Ok(s) => s,
                Err(e) => {
                    println!("Failed to create scriptPubKey: {}", e);
                    return;
                }
            };
            let tx_data = match PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()) {
                Ok(d) => d,
                Err(e) => {
                    println!("Failed to precompute transaction data: {}", e);
                    return;
                }
            };

            match ScriptTrace::from_verify(
                &spk,
                Some(self.amount),
                &tx,
                self.input_index,
                Some(self.flags),
                &tx_data,
            ) {
                Ok(trace) => {
                    let len = trace.len();
                    if let Some(err) = trace.error() {
                        println!("Script error: {}", err);
                    }
                    println!("Trace captured: {} step(s).", len);
                    self.trace = Some(trace);
                    self.cursor = 0;
                    if len > 0 {
                        self.print_current_frame();
                    }
                }
                Err(e) => println!("Run failed: {}", e),
            }
        } else {
            println!("Nothing to run \u{2014} load a tx or script first.");
        }
    }

    fn cmd_step(&mut self) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        let len = trace.len();
        if len == 0 {
            println!("Trace is empty.");
            return;
        }
        if self.cursor >= len - 1 {
            println!("End of trace (step {}/{}).", self.cursor, len - 1);
            return;
        }
        self.cursor += 1;
        self.print_current_frame();
    }

    fn cmd_back(&mut self) {
        if self.trace.is_none() {
            println!("No trace. Run first.");
            return;
        }
        if self.cursor == 0 {
            println!("Already at start.");
            return;
        }
        self.cursor -= 1;
        self.print_current_frame();
    }

    fn cmd_goto(&mut self, val: &str) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        let len = trace.len();
        if len == 0 {
            println!("Trace is empty.");
            return;
        }
        match val.parse::<usize>() {
            Ok(n) => {
                let target = n.min(len - 1);
                if n != target {
                    println!("Step {} is out of range, clamped to {}.", n, target);
                }
                self.cursor = target;
                self.print_current_frame();
            }
            Err(_) => println!("Invalid step number: {}", val),
        }
    }

    fn cmd_continue(&mut self) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        let len = trace.len();
        if len == 0 {
            println!("Trace is empty.");
            return;
        }
        // Find next breakpoint after cursor
        let mut next_bp: Option<usize> = None;
        for &bp in &self.breakpoints {
            if bp > self.cursor && (next_bp.is_none() || bp < next_bp.unwrap()) {
                next_bp = Some(bp);
            }
        }
        match next_bp {
            Some(bp) => {
                let target = bp.min(len - 1);
                if bp != target {
                    println!(
                        "Breakpoint {} clamped to end of trace (step {}).",
                        bp, target
                    );
                } else {
                    println!("Hit breakpoint at step {}.", target);
                }
                self.cursor = target;
                self.print_current_frame();
            }
            None => {
                self.cursor = len - 1;
                println!("No breakpoint ahead \u{2014} advanced to end of trace.");
                self.print_current_frame();
            }
        }
    }

    fn cmd_break(&mut self, val: &str) {
        match val.parse::<usize>() {
            Ok(n) => {
                if let Some(ref trace) = self.trace {
                    if n >= trace.len() {
                        println!(
                            "Warning: breakpoint {} is beyond trace length ({}).",
                            n,
                            trace.len()
                        );
                    }
                }
                self.breakpoints.insert(n);
                println!("Breakpoint set at step {}.", n);
            }
            Err(_) => println!("Invalid step number: {}", val),
        }
    }

    fn cmd_print_stack(&self) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        let frame = match trace.get(self.cursor) {
            Some(f) => f,
            None => {
                println!("No frame at cursor {}.", self.cursor);
                return;
            }
        };
        if frame.stack.is_empty() {
            println!("Stack is empty.");
        } else {
            println!("Stack:");
            for (i, item) in frame.stack.iter().enumerate() {
                if item.is_empty() {
                    println!("  {}: <empty>", i);
                } else {
                    println!("  {}: 0x{}", i, hex::encode(item));
                }
            }
        }
        if !frame.altstack.is_empty() {
            println!("Altstack:");
            for (i, item) in frame.altstack.iter().enumerate() {
                if item.is_empty() {
                    println!("  {}: <empty>", i);
                } else {
                    println!("  {}: 0x{}", i, hex::encode(item));
                }
            }
        }
    }

    fn cmd_print_script(&self) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        let frame = match trace.get(self.cursor) {
            Some(f) => f,
            None => {
                println!("No frame at cursor {}.", self.cursor);
                return;
            }
        };
        let script = Script::from_bytes(&frame.script);
        println!("Script:");
        for (i, op) in script.instructions().enumerate() {
            let marker = if i as u32 == frame.opcode_pos {
                "  > "
            } else {
                "    "
            };
            match op {
                Ok(instruction) => println!("{}{:?}", marker, instruction),
                Err(e) => println!("{}Error: {}", marker, e),
            }
        }
    }

    fn cmd_print_frame(&self) {
        let trace = match self.trace.as_ref() {
            Some(t) => t,
            None => {
                println!("No trace. Run first.");
                return;
            }
        };
        match trace.get(self.cursor) {
            Some(frame) => print_frame_display(frame, self.cursor, trace.len()),
            None => println!("No frame at cursor {}.", self.cursor),
        }
    }

    fn cmd_info(&self) {
        let mode = if self.bare_script.is_some() {
            "bare script"
        } else if self.spending_tx_bytes.is_some() {
            "transaction"
        } else {
            "none"
        };
        println!("Mode: {}", mode);

        if let Some(ref bytes) = self.spending_tx_bytes {
            let hex_str = hex::encode(bytes);
            let preview = if hex_str.len() > 40 {
                format!("{}...", &hex_str[..40])
            } else {
                hex_str
            };
            println!("Transaction: {}", preview);
        }
        if let Some(ref spk) = self.script_pubkey {
            println!("scriptPubKey: 0x{}", hex::encode(spk));
        }
        if let Some(ref script) = self.bare_script {
            println!("Bare script: 0x{}", hex::encode(script));
        }
        if !self.initial_stack.is_empty() {
            println!("Initial stack ({} item(s)):", self.initial_stack.len());
            for (i, item) in self.initial_stack.iter().enumerate() {
                println!("  {}: 0x{}", i, hex::encode(item));
            }
        }
        println!("Amount: {}", self.amount);
        println!("Input index: {}", self.input_index);
        println!("Flags: 0x{:08x} ({})", self.flags, flags_name(self.flags));

        match self.trace.as_ref() {
            Some(t) => {
                println!("Trace: {} step(s), cursor at {}", t.len(), self.cursor);
                if let Some(err) = t.error() {
                    println!("Script error: {}", err);
                }
            }
            None => println!("Trace: none"),
        }

        if !self.breakpoints.is_empty() {
            let mut bps: Vec<usize> = self.breakpoints.iter().copied().collect();
            bps.sort();
            println!(
                "Breakpoints: {}",
                bps.iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    fn cmd_help() {
        println!(
            "\
Commands:
  load tx <hex>          Load a spending transaction
  load script <hex>      Load a bare script for isolated execution
  set scriptpubkey <hex> Set the scriptPubKey (alias: set spk)
  set amount <n>         Set the spent output amount (satoshis)
  set flags <names>      Set verification flags (e.g. P2SH|WITNESS)
  set input <n>          Set the input index to verify
  stack push <hex>       Push an item onto the initial stack (bare mode)
  stack clear            Clear the initial stack
  run                    Execute and capture trace
  step, s                Advance one step
  back, b                Go back one step
  goto <n>               Jump to step N
  continue, c            Run to next breakpoint or end
  break <n>              Set breakpoint at step N
  break clear            Clear all breakpoints
  print stack, ps        Show stack at current step
  print script, psc      Show script disassembly at current step
  print frame, p         Show full frame at current step
  info, i                Show session summary
  reset                  Clear all state
  help, h                Show this help
  quit, exit, q          Exit the debugger"
        );
    }

    fn print_current_frame(&self) {
        if let Some(ref trace) = self.trace {
            if let Some(frame) = trace.get(self.cursor) {
                print_frame_display(frame, self.cursor, trace.len());
            }
        }
    }
}

fn print_frame_display(frame: &ScriptDebugFrame, cursor: usize, total: usize) {
    let sig_ver = match frame.sig_version {
        SigVersion::Base => "BASE",
        SigVersion::WitnessV0 => "WITNESS_V0",
        SigVersion::Taproot => "TAPROOT",
        SigVersion::Tapscript => "TAPSCRIPT",
        _ => "UNKNOWN",
    };
    println!(
        "[step {}/{}] opcode=0x{:02x} ({}) op_count={} f_exec={} sig_version={}",
        cursor,
        total - 1,
        frame.opcode,
        opcode_name(frame.opcode),
        frame.op_count,
        frame.f_exec,
        sig_ver,
    );
    if let Some(hash) = &frame.tapleaf_hash {
        println!("  Tapleaf hash: 0x{}", hex::encode(hash));
    }
    if frame.codeseparator_pos != 0xFFFFFFFF {
        println!("  OP_CODESEPARATOR pos: {}", frame.codeseparator_pos);
    }

    if !frame.stack.is_empty() {
        println!("  Stack:");
        for (i, item) in frame.stack.iter().enumerate() {
            if item.is_empty() {
                println!("    {}: <empty>", i);
            } else {
                println!("    {}: 0x{}", i, hex::encode(item));
            }
        }
    }

    if !frame.altstack.is_empty() {
        println!("  Altstack:");
        for (i, item) in frame.altstack.iter().enumerate() {
            if item.is_empty() {
                println!("    {}: <empty>", i);
            } else {
                println!("    {}: 0x{}", i, hex::encode(item));
            }
        }
    }

    let script = Script::from_bytes(&frame.script);
    println!("  Script:");
    for (i, op) in script.instructions().enumerate() {
        let marker = if i as u32 == frame.opcode_pos {
            "  > "
        } else {
            "    "
        };
        match op {
            Ok(instruction) => println!("{}{:?}", marker, instruction),
            Err(e) => println!("{}Error: {}", marker, e),
        }
    }
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "OP_0",
        0x01..=0x4b => "OP_PUSHBYTES",
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "OP_1NEGATE",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        0x61 => "OP_NOP",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x7c => "OP_SWAP",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xba => "OP_CHECKSIGADD",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

fn flags_name(flags: u32) -> String {
    if flags == VERIFY_NONE {
        return "NONE".to_string();
    }
    if flags == VERIFY_ALL {
        return "ALL".to_string();
    }
    if flags == VERIFY_ALL_PRE_TAPROOT {
        return "ALL_PRE_TAPROOT".to_string();
    }
    let mut names = Vec::new();
    if flags & VERIFY_P2SH != 0 {
        names.push("P2SH");
    }
    if flags & VERIFY_DERSIG != 0 {
        names.push("DERSIG");
    }
    if flags & VERIFY_NULLDUMMY != 0 {
        names.push("NULLDUMMY");
    }
    if flags & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
        names.push("CHECKLOCKTIMEVERIFY");
    }
    if flags & VERIFY_CHECKSEQUENCEVERIFY != 0 {
        names.push("CHECKSEQUENCEVERIFY");
    }
    if flags & VERIFY_WITNESS != 0 {
        names.push("WITNESS");
    }
    if flags & VERIFY_TAPROOT != 0 {
        names.push("TAPROOT");
    }
    if names.is_empty() {
        format!("0x{:08x}", flags)
    } else {
        names.join("|")
    }
}

fn main() {
    let mut rl = rustyline::DefaultEditor::new().expect("failed to create editor");
    let mut session = Session::new();

    println!("Bitcoin Script Debugger");
    println!("Type 'help' for available commands.\n");

    loop {
        match rl.readline("debug> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(line).ok();
                if line == "quit" || line == "exit" || line == "q" {
                    break;
                }
                session.handle_command(line);
            }
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => break,
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
}
