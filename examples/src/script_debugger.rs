use std::process;

use bitcoinkernel::{
    trace_verify, PrecomputedTransactionData, ScriptPubkey, ScriptTrace,
    StackItem, Transaction, TxOut, VERIFY_ALL_PRE_TAPROOT,
};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_stack(stack: &[StackItem]) -> String {
    if stack.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<String> = stack
        .iter()
        .map(|item| {
            if item.is_empty() {
                "<empty>".to_string()
            } else if item.len() > 8 {
                format!("{}({})", hex_encode(&item.as_bytes()[..4]), item.len())
            } else {
                format!("{}", item)
            }
        })
        .collect();
    format!("[{}]", items.join(", "))
}

fn print_trace(trace: &ScriptTrace, verbose: bool) {
    let mut current_phase = None;

    for step in trace.iter() {
        // Print phase header on change
        if current_phase != Some(step.phase) {
            current_phase = Some(step.phase);
            println!();
            println!("=== Phase: {} ===", step.phase);
        }

        let opcode_name = match &step.instruction {
            Some(instr) => instr.opcode.name(),
            None => format!("(end, pos={})", step.opcode_pos),
        };

        let push_data_str = match &step.instruction {
            Some(instr) => match &instr.push_data {
                Some(data) if !data.is_empty() => {
                    if data.len() > 16 {
                        format!(" -> 0x{}...", hex_encode(&data[..16]))
                    } else {
                        format!(" -> 0x{}", hex_encode(data))
                    }
                }
                _ => String::new(),
            },
            None => String::new(),
        };

        if verbose {
            println!(
                "  [{}] {}{}",
                step.step_index, opcode_name, push_data_str,
            );
            println!("      Stack: {}", format_stack(&step.stack));
            if !step.altstack.is_empty() {
                println!("      AltStack: {}", format_stack(&step.altstack));
            }
        } else {
            println!(
                "  [{}] {:<24} Stack: {}",
                step.step_index,
                format!("{}{}", opcode_name, push_data_str),
                format_stack(&step.stack),
            );
        }
    }

    println!();
    if trace.success {
        println!("Result: PASS");
    } else {
        println!("Result: FAIL - {}", trace.error.as_deref().unwrap_or("unknown"));
    }
}

fn print_trace_json(trace: &ScriptTrace) {
    println!("{{");
    println!("  \"success\": {},", trace.success);
    if let Some(ref err) = trace.error {
        println!("  \"error\": \"{}\",", err);
    }
    println!("  \"step_count\": {},", trace.len());
    println!("  \"phases\": [{}],", trace.phases().iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(", "));
    println!("  \"steps\": [");
    for (i, step) in trace.iter().enumerate() {
        let comma = if i + 1 < trace.len() { "," } else { "" };
        let opcode = match &step.instruction {
            Some(instr) => instr.opcode.name(),
            None => format!("END(pos={})", step.opcode_pos),
        };
        let stack: Vec<String> = step.stack.iter().map(|s| format!("\"{}\"", hex_encode(s.as_bytes()))).collect();
        println!(
            "    {{\"index\": {}, \"phase\": \"{}\", \"opcode\": \"{}\", \"stack\": [{}]}}{}",
            step.step_index, step.phase, opcode, stack.join(", "), comma
        );
    }
    println!("  ]");
    println!("}}");
}

fn run_builtin_p2pkh() {
    println!("--- Built-in test: P2PKH ---");

    let script_pubkey_hex = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";
    let spending_tx_hex = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";

    let script_pubkey = ScriptPubkey::try_from(hex_decode(script_pubkey_hex).as_slice()).unwrap();
    let tx = Transaction::new(hex_decode(spending_tx_hex).as_slice()).unwrap();
    let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

    let trace = trace_verify(
        &script_pubkey,
        Some(0),
        &tx,
        0,
        Some(VERIFY_ALL_PRE_TAPROOT),
        &tx_data,
    );

    print_trace(&trace, true);
}

fn run_builtin_p2sh_segwit() {
    println!("--- Built-in test: P2SH-P2WPKH ---");

    let script_pubkey_hex = "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87";
    let spending_tx_hex = "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000";
    let amount: i64 = 1900000;

    let script_pubkey = ScriptPubkey::try_from(hex_decode(script_pubkey_hex).as_slice()).unwrap();
    let tx = Transaction::new(hex_decode(spending_tx_hex).as_slice()).unwrap();
    let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

    let trace = trace_verify(
        &script_pubkey,
        Some(amount),
        &tx,
        0,
        Some(VERIFY_ALL_PRE_TAPROOT),
        &tx_data,
    );

    print_trace(&trace, true);
}

fn print_usage() {
    eprintln!("Bitcoin Script Debugger");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  script_debugger --builtin                      Run built-in test vectors");
    eprintln!("  script_debugger --script-pubkey <hex> --spending-tx <hex> [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --script-pubkey <hex>   ScriptPubKey to verify against");
    eprintln!("  --spending-tx <hex>     Raw spending transaction");
    eprintln!("  --amount <sats>         Amount in satoshis (default: 0)");
    eprintln!("  --input-index <n>       Input index to verify (default: 0)");
    eprintln!("  --format <mode>         Output format: compact, verbose, json (default: verbose)");
    eprintln!("  --builtin               Run built-in test vectors");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let mut script_pubkey_hex: Option<String> = None;
    let mut spending_tx_hex: Option<String> = None;
    let mut amount: i64 = 0;
    let mut input_index: usize = 0;
    let mut format_mode = "verbose".to_string();
    let mut builtin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--script-pubkey" => {
                i += 1;
                script_pubkey_hex = Some(args[i].clone());
            }
            "--spending-tx" => {
                i += 1;
                spending_tx_hex = Some(args[i].clone());
            }
            "--amount" => {
                i += 1;
                amount = args[i].parse().expect("Invalid amount");
            }
            "--input-index" => {
                i += 1;
                input_index = args[i].parse().expect("Invalid input index");
            }
            "--format" => {
                i += 1;
                format_mode = args[i].clone();
            }
            "--builtin" => {
                builtin = true;
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    if builtin {
        run_builtin_p2pkh();
        println!();
        run_builtin_p2sh_segwit();
        return;
    }

    let spk_hex = match script_pubkey_hex {
        Some(h) => h,
        None => {
            eprintln!("Error: --script-pubkey is required");
            print_usage();
            process::exit(1);
        }
    };

    let tx_hex = match spending_tx_hex {
        Some(h) => h,
        None => {
            eprintln!("Error: --spending-tx is required");
            print_usage();
            process::exit(1);
        }
    };

    let script_pubkey = match ScriptPubkey::try_from(hex_decode(&spk_hex).as_slice()) {
        Ok(spk) => spk,
        Err(e) => {
            eprintln!("Error creating script pubkey: {}", e);
            process::exit(1);
        }
    };

    let tx = match Transaction::new(hex_decode(&tx_hex).as_slice()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error creating transaction: {}", e);
            process::exit(1);
        }
    };

    let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

    let trace = trace_verify(
        &script_pubkey,
        Some(amount),
        &tx,
        input_index,
        Some(VERIFY_ALL_PRE_TAPROOT),
        &tx_data,
    );

    match format_mode.as_str() {
        "json" => print_trace_json(&trace),
        "compact" => print_trace(&trace, false),
        _ => print_trace(&trace, true),
    }
}
