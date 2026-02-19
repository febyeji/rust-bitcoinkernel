use clap::{Parser, ValueEnum};
use colored::Colorize;

use bitcoinkernel::{
    trace_verify, PrecomputedTransactionData, ScriptExecError, ScriptPhase, ScriptPubkey,
    ScriptTrace, StackItem, Transaction, TxOut, VERIFY_ALL_PRE_TAPROOT,
};

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "script_debugger",
    about = "Step-by-step Bitcoin Script execution tracer",
)]
struct Args {
    /// ScriptPubKey of the output being spent (hex)
    #[arg(long, value_name = "HEX")]
    script_pubkey: Option<String>,

    /// Raw spending transaction (hex)
    #[arg(long, value_name = "HEX")]
    spending_tx: Option<String>,

    /// Value of the input being spent, in satoshis
    #[arg(long, default_value = "0", value_name = "SATS")]
    amount: i64,

    /// Index of the input to verify
    #[arg(long, default_value = "0", value_name = "N")]
    input_index: usize,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Default)]
    format: Format,

    /// Run built-in test vectors (P2PKH and P2SH-P2WPKH)
    #[arg(long)]
    builtin: bool,
}

#[derive(ValueEnum, Clone)]
enum Format {
    Default,
    Json,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── stack rendering ──────────────────────────────────────────────────────────

fn render_item(item: &StackItem) -> String {
    let b = item.as_bytes();
    if b.is_empty()   { return "∅".into(); }
    if b == [1]       { return "TRUE".green().bold().to_string(); }
    if b == [0]       { return "FALSE".red().to_string(); }
    if let Some(n) = item.as_script_num() { return n.to_string(); }
    let preview = hex_encode(&b[..b.len().min(4)]);
    format!("{}…·{}", preview, b.len()).dimmed().to_string()
}

fn render_stack(stack: &[StackItem]) -> String {
    if stack.is_empty() {
        return "(empty)".dimmed().to_string();
    }
    stack.iter().map(render_item).collect::<Vec<_>>().join("  ")
}

// ─── printer ─────────────────────────────────────────────────────────────────

fn phase_color(phase: ScriptPhase) -> colored::Color {
    match phase {
        ScriptPhase::ScriptSig      => colored::Color::Cyan,
        ScriptPhase::ScriptPubKey   => colored::Color::Blue,
        ScriptPhase::RedeemScript   => colored::Color::Magenta,
        ScriptPhase::WitnessScript  => colored::Color::Yellow,
        ScriptPhase::Unknown        => colored::Color::White,
    }
}

// Mimics cargo's right-aligned bold label style, e.g. "   Compiling foo"
fn label(tag: &str, content: &str) {
    println!("{:>12}  {}", tag.bold().green(), content);
}

fn print_trace(trace: &ScriptTrace) {
    let steps: Vec<_> = trace.iter().collect();
    let mut current_phase: Option<ScriptPhase> = None;
    let mut display_idx: usize = 0;

    for (i, step) in steps.iter().enumerate() {
        let is_end = step.instruction.is_none();

        // Phase header
        if !is_end && current_phase != Some(step.phase) {
            current_phase = Some(step.phase);
            let c = phase_color(step.phase);
            println!();
            println!("{:>12}  {}", "phase".dimmed(), step.phase.to_string().color(c).bold());
        }

        if is_end {
            continue;
        }

        let instr = step.instruction.as_ref().unwrap();
        let c = phase_color(step.phase);

        // Push-data preview on the same line as the opcode
        let push_str = match &instr.push_data {
            Some(data) if !data.is_empty() => {
                let s = if data.len() > 18 {
                    format!("{}…", hex_encode(&data[..18]))
                } else {
                    hex_encode(data)
                };
                format!("  {}", s.dimmed())
            }
            _ => String::new(),
        };

        println!(
            "  {:>3}  {}{}",
            display_idx.to_string().color(c).dimmed(),
            instr.opcode.name().color(c).bold(),
            push_str,
        );
        display_idx += 1;

        // Stack after this opcode (next step's before-state)
        if let Some(next) = steps.get(i + 1) {
            println!(
                "       {}  {}",
                "stack".dimmed(),
                render_stack(&next.stack)
            );
            if !next.altstack.is_empty() {
                println!(
                    "         {}  {}",
                    "alt".dimmed(),
                    render_stack(&next.altstack)
                );
            }
        }
    }

    println!();

    if trace.success {
        let phases = trace.phases().len();
        println!(
            "{:>12}  {}  ({} phases, {} steps)",
            "ok".bold().green(),
            "verification passed",
            phases,
            display_idx,
        );
    } else {
        println!(
            "{:>12}  {}",
            "error".bold().red(),
            trace.error.as_deref().unwrap_or("verification failed").red(),
        );
        if let Some(se) = &trace.script_error {
            if *se != ScriptExecError::Ok {
                println!("{:>12}  {:?}", "note".bold(), se);
            }
        }
    }
}

fn print_json(trace: &ScriptTrace) {
    let steps: Vec<_> = trace.iter().collect();
    println!("{{");
    println!("  \"success\": {},", trace.success);
    if let Some(ref e) = trace.error {
        println!("  \"error\": \"{}\",", e);
    }
    if let Some(ref se) = trace.script_error {
        println!("  \"script_error\": \"{:?}\",", se);
    }
    println!(
        "  \"phases\": [{}],",
        trace.phases().iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(", ")
    );
    println!("  \"steps\": [");
    let real: Vec<_> = steps.iter().enumerate().filter(|(_, s)| s.instruction.is_some()).collect();
    for (n, (i, step)) in real.iter().enumerate() {
        let comma = if n + 1 < real.len() { "," } else { "" };
        let op = step.instruction.as_ref().unwrap().opcode.name();
        let after: Vec<String> = steps
            .get(i + 1)
            .map(|s| s.stack.iter().map(|it| format!("\"{}\"", hex_encode(it.as_bytes()))).collect())
            .unwrap_or_default();
        println!(
            "    {{\"step\": {}, \"phase\": \"{}\", \"opcode\": \"{}\", \"stack_after\": [{}]}}{}",
            n, step.phase, op, after.join(", "), comma
        );
    }
    println!("  ]\n}}");
}

// ─── built-in test vectors ────────────────────────────────────────────────────

fn run(title: &str, spk_hex: &str, tx_hex: &str, amount: i64, input: usize, fmt: &Format) {
    label("Verifying", &format!("{} (input #{}, {} sat)", title, input, amount));
    println!("{:>12}  {}", "scriptPubKey".dimmed(), spk_hex.dimmed());

    let spk = ScriptPubkey::try_from(hex_decode(spk_hex).as_slice()).unwrap();
    let tx  = Transaction::new(hex_decode(tx_hex).as_slice()).unwrap();
    let txd = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();
    let trace = trace_verify(&spk, Some(amount), &tx, input, Some(VERIFY_ALL_PRE_TAPROOT), &txd);

    match fmt {
        Format::Json    => print_json(&trace),
        Format::Default => print_trace(&trace),
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    if args.builtin {
        run(
            "P2PKH",
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95\
             000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c36\
             02201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9\
             e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25\
             d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999\
             d54d59f67c019e756c88ac6acb0700",
            0, 0, &args.format,
        );
        println!();
        run(
            "P2SH-P2WPKH",
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df\
             0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914\
             233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51\
             b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7\
             f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            1_900_000, 0, &args.format,
        );
        return;
    }

    let spk_hex = args.script_pubkey.unwrap_or_else(|| {
        eprintln!("{}: --script-pubkey is required (or use --builtin)", "error".red().bold());
        std::process::exit(1);
    });
    let tx_hex = args.spending_tx.unwrap_or_else(|| {
        eprintln!("{}: --spending-tx is required (or use --builtin)", "error".red().bold());
        std::process::exit(1);
    });

    run("", &spk_hex, &tx_hex, args.amount, args.input_index, &args.format);
}
