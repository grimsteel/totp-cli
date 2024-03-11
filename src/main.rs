mod base32;
mod totp;
mod secret_storage;
mod utils;

use std::process::ExitCode;
use std::time::Duration;
use std::thread::sleep;

use clap::{Parser, Subcommand};
use secret_storage::delete_token;

use crate::base32::{base32decode, validate_base32};
use crate::totp::get_current_token;
use crate::secret_storage::{get_token, make_schema, store_token, TokenInfo};
use crate::utils::{get_hidden_input, parse_otpauth_uri};

const ONE_SECOND: Duration  = Duration::from_secs(1);

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a TOTP for a specified token
    Get {
        /// The id of the account to generate a token for
        id: String,

        /// Show a live countdown and update the token when necessary 
        #[arg(short, long)]
        interactive: bool,

        /// Only print the token
        #[arg(short, long)]
        quiet: bool
    },
    /// Add a new account
    Add {
        /// The account id, for use in the terminal
        id: String,
        
        /// The human readable account label
        label: String,
        
        /// The issuer (website name)
        issuer: String,
        
        /// The base32 encoded token. Omit for stdin
        #[arg(value_parser = |s: &_| validate_base32(s))]
        token: Option<String>
    },
    Delete {
        id: String
    },
    /// Import a new account from an "otpauth://" URI
    Import {
        id: String,
        
        /// Omit for stdin
        #[arg(value_parser = |s: &_| parse_otpauth_uri(s))]
        otpauth_uri: Option<TokenInfo>
    }
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let secret_schema = make_schema();

    match &cli.command {
        Commands::Add { id, label, issuer, token } => {
            let token = match token.clone().or_else(|| get_hidden_input("Token: ").ok()) {
                Some(t) => t,
                None => {
                    eprintln!("Could not read from stdin!");
                    return ExitCode::from(100);
                }
            };

            match store_token(&secret_schema, label, id, issuer, &token) {
                Some(_) => ExitCode::from(0),
                None => {
                    eprintln!("Could not store token in secret storage");
                    ExitCode::from(101)
                }
            }
        },
        Commands::Import { id, otpauth_uri } => {
            let token_info = otpauth_uri.clone()
                // if it wasn't provided,
                .or_else(
                    ||
                        // get from stdin
                        get_hidden_input("otpauth URI: ")
                        // we don't care about error
                        .ok()
                        // and parse
                        .and_then(|s| parse_otpauth_uri(&s).ok())
                );
            
            match token_info {
                Some(TokenInfo { issuer, token, label }) => {
                    // Store this token
                    match store_token(&secret_schema, &label, id, &issuer, &token.to_string()) {
                        Some(_) => ExitCode::from(0),
                        None => {
                            eprintln!("Could not store token in secret storage");
                            ExitCode::from(101)
                        }
                    }
                },
                _ => {
                    eprintln!("Invalid URI");
                    ExitCode::from(102)
                }
            }
        },
        Commands::Delete { id } => {
            match delete_token(&secret_schema, id) {
                Some(()) => ExitCode::from(0),
                _ => {
                    eprintln!("Could not find token");
                    ExitCode::from(103)
                }
            }
        },
        Commands::Get { id, interactive, quiet } => {
            match get_token(&secret_schema, id) {
                Some(token) => {
                    match base32decode(&token.token) {
                        Some(decoded) => {
                            loop {
                                let (code, time_left) = get_current_token(&decoded);

                                if *quiet {
                                    println!("{:06}\x1b[K", code);
                                } else {
                                    println!("Token for {} ({}): {:06}\x1b[K", token.issuer, token.label, code);
                                    println!("Valid for {:02}s\x1b[K", time_left);
                                }

                                // Only display the token once if not interactive
                                if !interactive {
                                    break;
                                }

                                sleep(ONE_SECOND);

                                // Move back up
                                if *quiet {
                                    print!("\x1b[F");
                                } else {
                                    print!("\x1b[2F");
                                }
                            }
                            ExitCode::from(0)
                        },
                        _ => {
                            eprintln!("Corrupted token: {}", token.token);
                            ExitCode::from(104)
                        }
                    }
                },
                _ => {
                    eprintln!("Could not find token");
                    ExitCode::from(103)
                }
            }
        }
    }
}
