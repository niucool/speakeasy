// Command-line interface

use clap::{Parser, Subcommand};
use colored::*;
use log::info;
use speakeasy::{SpeakeasyConfig, Speakeasy};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "speakeasy")]
#[command(about = "Windows malware emulation framework", long_about = None)]
#[command(version)]
struct Args {
    /// Target binary or shellcode
    #[arg(short, long)]
    target: Option<String>,

    /// Output report file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Raw shellcode mode (specify architecture with --arch)
    #[arg(long)]
    do_raw: bool,

    /// Architecture for raw mode (x86 or x64)
    #[arg(long)]
    arch: Option<String>,

    /// Raw offset for raw mode
    #[arg(long)]
    raw_offset: Option<u64>,

    /// Entry point address
    #[arg(long)]
    entry_point: Option<String>,

    /// Emulate child processes
    #[arg(long)]
    emulate_children: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Path to save dropped files archive
    #[arg(long)]
    dropped_files_path: Option<PathBuf>,

    /// GDB debugging port
    #[arg(long)]
    gdb_port: Option<u16>,

    /// Disable multiprocessing
    #[arg(long)]
    no_mp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run emulation on a target
    Run {
        /// Target file
        target: PathBuf,
    },
    /// Generate default configuration
    Config {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show version information
    Version,
}

fn setup_logging(verbose: bool) {
    let _level = if verbose { "debug" } else { "info" };
    env_logger::Builder::from_default_env()
        .filter(None, log::LevelFilter::Info)
        .format_timestamp_millis()
        .init();
}

fn run(args: &Args) -> speakeasy::errors::Result<()> {
    match &args.command {
        Some(Commands::Version) => {
            // speakeasy::VERSION might not exist depending on lib.rs, assuming it does based on original code
            println!("{}", format!("speakeasy v3.0").cyan());
            Ok(())
        }
        Some(Commands::Config { output }) => {
            let config = SpeakeasyConfig::default();
            let json = config.to_json()?;
            
            if let Some(out) = output {
                if let Err(e) = fs::write(out, json) {
                    return Err(speakeasy::errors::SpeakeasyError::Unknown(e.to_string()));
                }
                info!("Configuration written to {}", out.display());
            } else {
                println!("{}", json);
            }
            Ok(())
        }
        _ => {
            // Default run behavior
            if let Some(target) = &args.target {
                run_emulation(target, args)?;
            } else if let Some(Commands::Run { target }) = &args.command {
                run_emulation(target.to_str().unwrap(), args)?;
            } else {
                eprintln!("{}", "Error: No target specified".red());
                eprintln!("Use: speakeasy --help for usage information");
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn main() {
    let args = Args::parse();
    setup_logging(args.verbose);

    if let Err(e) = run(&args) {
        eprintln!("{}: {}", "Error".red(), e);
        std::process::exit(1);
    }
}

fn run_emulation(target: &str, args: &Args) -> speakeasy::errors::Result<()> {
    info!("Loading target: {}", target);

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        SpeakeasyConfig::from_file(config_path.to_str().unwrap())?
    } else {
        SpeakeasyConfig::default()
    };

    // Create emulator
    let emulator = Speakeasy::new(Some(config))?;

    // Load target
    if args.do_raw {
        let data = fs::read(target)?;
        let _addr = emulator.load_shellcode(&data, args.arch.as_deref().unwrap_or("x86"))?;
        info!("Executing shellcode from {}", target);
        emulator.run_shellcode(0x400000)?;
    } else {
        let module_name = emulator.load_module(target)?;
        info!("Executing module: {}", target);
        emulator.run_module(&module_name)?;
    }

    // Get report
    let json_report = emulator.get_json_report()?;

    // Output report
    if let Some(output) = &args.output {
        info!("Writing report to {}", output.display());
        fs::write(output, &json_report)?;
    } else {
        println!("{}", json_report);
    }

    Ok(())
}
