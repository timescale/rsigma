use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use rsigma_parser::{parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};

#[derive(Parser)]
#[command(name = "rsigma")]
#[command(about = "Parse, validate, and evaluate Sigma detection rules")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a single Sigma YAML file and print the AST as JSON
    Parse {
        /// Path to a Sigma YAML file
        path: PathBuf,

        /// Pretty-print JSON output
        #[arg(short, long, default_value_t = true)]
        pretty: bool,
    },

    /// Parse all Sigma rules in a directory (recursive) and report results
    Validate {
        /// Path to a directory containing Sigma YAML files
        path: PathBuf,

        /// Show details for each file (not just summary)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Parse a condition expression and print the AST
    Condition {
        /// The condition expression to parse
        expr: String,
    },

    /// Read Sigma YAML from stdin and print parsed AST as JSON
    Stdin {
        /// Pretty-print JSON output
        #[arg(short, long, default_value_t = true)]
        pretty: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { path, pretty } => {
            match parse_sigma_file(&path) {
                Ok(collection) => {
                    if !collection.errors.is_empty() {
                        eprintln!("Warnings:");
                        for err in &collection.errors {
                            eprintln!("  - {err}");
                        }
                    }
                    let json = if pretty {
                        serde_json::to_string_pretty(&collection)
                    } else {
                        serde_json::to_string(&collection)
                    };
                    match json {
                        Ok(j) => println!("{j}"),
                        Err(e) => {
                            eprintln!("JSON serialization error: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error parsing {}: {e}", path.display());
                    process::exit(1);
                }
            }
        }

        Commands::Validate { path, verbose } => {
            match parse_sigma_directory(&path) {
                Ok(collection) => {
                    let total = collection.len();
                    let rules = collection.rules.len();
                    let correlations = collection.correlations.len();
                    let filters = collection.filters.len();
                    let errors = collection.errors.len();

                    println!("Parsed {total} documents from {}", path.display());
                    println!("  Detection rules:  {rules}");
                    println!("  Correlation rules: {correlations}");
                    println!("  Filter rules:     {filters}");
                    println!("  Parse errors:     {errors}");

                    if verbose && !collection.errors.is_empty() {
                        println!("\nErrors:");
                        for err in &collection.errors {
                            println!("  - {err}");
                        }
                    }

                    if errors > 0 {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Condition { expr } => {
            match rsigma_parser::parse_condition(&expr) {
                Ok(ast) => {
                    match serde_json::to_string_pretty(&ast) {
                        Ok(j) => println!("{j}"),
                        Err(e) => {
                            eprintln!("JSON serialization error: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Condition parse error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Stdin { pretty } => {
            let mut input = String::new();
            if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input) {
                eprintln!("Error reading stdin: {e}");
                process::exit(1);
            }

            match parse_sigma_yaml(&input) {
                Ok(collection) => {
                    if !collection.errors.is_empty() {
                        eprintln!("Warnings:");
                        for err in &collection.errors {
                            eprintln!("  - {err}");
                        }
                    }
                    let json = if pretty {
                        serde_json::to_string_pretty(&collection)
                    } else {
                        serde_json::to_string(&collection)
                    };
                    match json {
                        Ok(j) => println!("{j}"),
                        Err(e) => {
                            eprintln!("JSON serialization error: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Parse error: {e}");
                    process::exit(1);
                }
            }
        }
    }
}
