use clap::Parser;
use colored::Colorize;
use log::info;
use std::fs;
use std::path::PathBuf;

use crate::cli_config::{apply_env_overrides, apply_module_paths, get_default_config_dict, load_merged_config};
use crate::config::SpeakeasyConfig;
use crate::errors::{Result, SpeakeasyError};
use crate::speakeasy::Speakeasy;
use crate::VERSION;

#[derive(Debug, Parser)]
#[command(name = "speakeasy", about = "Emulate a Windows binary with speakeasy", disable_help_subcommand = true)]
pub struct CliArgs {
    #[arg(short = 't', long)]
    pub target: Option<PathBuf>,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    #[arg(long, default_value = "")]
    pub argv: String,

    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub dump_default_config: bool,

    #[arg(long = "raw")]
    pub do_raw: bool,

    #[arg(long, value_parser = parse_hex_or_decimal_u64, default_value = "0")]
    pub raw_offset: u64,

    #[arg(long, value_parser = parse_hex_or_decimal_u64)]
    pub entry_point: Option<u64>,

    #[arg(long)]
    pub arch: Option<String>,

    #[arg(long)]
    pub dropped_files_path: Option<PathBuf>,

    #[arg(short = 'k', long)]
    pub emulate_children: bool,

    #[arg(long)]
    pub no_mp: bool,

    #[arg(short = 'v', long)]
    pub verbose: bool,

    #[arg(long)]
    pub gdb: bool,

    #[arg(long, default_value_t = 1234)]
    pub gdb_port: u16,

    #[arg(short = 'V', long = "volume")]
    pub volumes: Vec<String>,

    #[arg(long = "env")]
    pub env: Vec<String>,

    #[arg(long = "module-path")]
    pub module_paths: Vec<PathBuf>,
}

pub fn main() {
    let args = CliArgs::parse();
    setup_logging(args.verbose);

    if let Err(err) = run(args) {
        eprintln!("{}: {err}", "Error".red());
        std::process::exit(1);
    }
}

pub fn run(args: CliArgs) -> Result<()> {
    if args.dump_default_config {
        println!("{}", serde_json::to_string_pretty(&get_default_config_dict()?)?);
        return Ok(());
    }

    let Some(target) = args.target.as_ref() else {
        return Err(SpeakeasyError::ConfigError("no target file supplied".to_string()));
    };

    if !target.is_file() {
        return Err(SpeakeasyError::ConfigError(format!(
            "target file not found: {}",
            target.display()
        )));
    }

    let mut config = load_active_config(&args)?;
    if let Some(path) = args.dropped_files_path.as_ref() {
        config.file_system.dropped_files_path = path.clone();
    }
    config.process.emulate_children = args.emulate_children;
    apply_env_overrides(&mut config, &args.env)?;
    apply_module_paths(&mut config, &args.module_paths);

    if args.gdb && !args.no_mp {
        info!("--gdb requested; Rust port currently runs in-process regardless of --no-mp");
    }

    let report = emulate_binary(target, &config, &args)?;
    if let Some(output) = args.output.as_ref() {
        fs::write(output, &report)?;
        info!("saved emulation report to {}", output.display());
    } else {
        println!("{report}");
    }

    Ok(())
}

fn load_active_config(args: &CliArgs) -> Result<SpeakeasyConfig> {
    let mut config = load_merged_config(args.config.as_deref())?;
    if !args.argv.trim().is_empty() {
        config.process.command_line = args.argv.split_whitespace().map(str::to_string).collect();
    }
    Ok(config)
}

fn emulate_binary(target: &PathBuf, config: &SpeakeasyConfig, args: &CliArgs) -> Result<String> {
    let emulator = Speakeasy::new(Some(config.clone()))?;

    if args.do_raw {
        let data = fs::read(target)?;
        let arch = args.arch.as_deref().unwrap_or("x86");
        let address = emulator.load_shellcode(&data, arch)?;
        info!(
            "executing raw buffer from {} at offset 0x{:X} (entry override: {:?}, gdb: {})",
            target.display(),
            args.raw_offset,
            args.entry_point,
            args.gdb
        );
        emulator.run_shellcode(address + args.raw_offset)?;
    } else {
        let module_name = emulator.load_module(&target.to_string_lossy())?;
        info!(
            "executing module {} (entry override: {:?}, emulate_children: {})",
            target.display(),
            args.entry_point,
            args.emulate_children
        );
        emulator.run_module(&module_name)?;
    }

    emulator.get_json_report()
}

fn parse_hex_or_decimal_u64(raw: &str) -> std::result::Result<u64, String> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        trimmed.parse::<u64>().map_err(|err| err.to_string())
    }
}

fn setup_logging(verbose: bool) {
    let mut builder = env_logger::Builder::from_default_env();
    builder.filter_level(if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });
    let _ = builder.try_init();
    info!("speakeasy {}", VERSION.cyan());
}
