mod proxy;
mod runner;
mod store;

use clap::{Parser, Subcommand};
use proxy::{handle_single_request, start_proxy_server};
use runner::run_redacted;
use std::collections::BTreeMap;
use std::io;
use std::process::ExitCode;
use store::SecretStore;

#[derive(Parser, Debug)]
#[command(
    name = "agent-vault",
    version,
    about = "Zero-knowledge secret proxy and output redactor for AI agents and MCP servers."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Store a secret in the encrypted XChaCha20-Poly1305 vault
    Set {
        name: String,
        #[arg(long)]
        value: Option<String>,
    },
    /// List stored secret names (masked)
    List,
    /// Delete a secret from the vault
    Delete { name: String },
    /// Add an HTTP egress proxy route with secret header injection
    RouteAdd {
        name: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        header: Vec<String>,
        #[arg(long)]
        allow_insecure_http: bool,
    },
    /// Start the local secret-injecting HTTP proxy
    Proxy {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
    /// Run a command or MCP server with secret:// env vars and stdout/stderr redaction
    Run {
        #[arg(long)]
        env: Vec<String>,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Generate an mcpServers JSON snippet wrapped with agent-vault
    McpSnippet {
        server_name: String,
        #[arg(long)]
        env: Vec<String>,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

fn run_cli(cli: Cli, store: &SecretStore) -> Result<i32, String> {
    match cli.command {
        Commands::Set { name, value } => {
            let val = match value {
                Some(v) => v,
                None => rpassword::prompt_password(format!("Value for {}: ", name))
                    .map_err(|e| e.to_string())?,
            };
            store.set_secret(&name, &val)?;
            println!("Secret '{}' stored in encrypted vault.", name);
            Ok(0)
        }
        Commands::List => {
            let items = store.list_secrets()?;
            if items.is_empty() {
                println!("Vault is empty.");
            } else {
                for (k, preview) in items {
                    println!("  {}: {}", k, preview);
                }
            }
            Ok(0)
        }
        Commands::Delete { name } => {
            if store.delete_secret(&name)? {
                println!("Secret '{}' deleted.", name);
                Ok(0)
            } else {
                eprintln!("Secret '{}' not found.", name);
                Ok(1)
            }
        }
        Commands::RouteAdd {
            name,
            target,
            header,
            allow_insecure_http,
        } => {
            let mut map = BTreeMap::new();
            for h in header {
                let Some((k, v)) = h.split_once(':') else {
                    return Err(format!("Invalid header format: {}", h));
                };
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
            store.save_route(&name, &target, map, allow_insecure_http)?;
            println!("Route '{}' -> {} saved.", name, target);
            Ok(0)
        }
        Commands::Proxy { host, port } => {
            let server = start_proxy_server(store, &host, port)?;
            println!("agent-vault proxy listening on http://{}:{}", host, port);
            for (rname, rdata) in store.load_routes()? {
                println!(
                    "  http://{}:{}/r/{}/... -> {}",
                    host, port, rname, rdata.target
                );
            }
            for req in server.incoming_requests() {
                handle_single_request(req, store);
            }
            Ok(0)
        }
        Commands::Run { env, cmd } => run_redacted(&cmd, &env, store, io::stdout(), io::stderr()),
        Commands::McpSnippet {
            server_name,
            env,
            cmd,
        } => {
            let mut args = vec!["run".to_string()];
            for e in env {
                args.push("--env".to_string());
                args.push(e);
            }
            args.push("--".to_string());
            args.extend(cmd);
            let snippet = serde_json::json!({
                "mcpServers": {
                    server_name: {
                        "command": "agent-vault",
                        "args": args
                    }
                }
            });
            println!("{}", serde_json::to_string_pretty(&snippet).unwrap());
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let store = SecretStore::new(None, None);
    match run_cli(cli, &store) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::from(1)
        }
    }
}
