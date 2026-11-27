use crate::store::SecretStore;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;

pub fn resolve_env_bindings(
    bindings: &[String],
    store: &SecretStore,
) -> Result<HashMap<String, String>, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    for item in bindings {
        let Some((k, v)) = item.split_once('=') else {
            return Err(format!(
                "Invalid --env format (expected KEY=VALUE): {}",
                item
            ));
        };
        if let Some(sec_name) = v.strip_prefix("secret://") {
            let resolved = store
                .get_secret(sec_name)?
                .ok_or_else(|| format!("Secret '{}' not found in vault", sec_name))?;
            env.insert(k.to_string(), resolved.as_str().to_string());
        } else {
            env.insert(k.to_string(), v.to_string());
        }
    }
    Ok(env)
}

pub fn run_redacted<W1, W2>(
    cmd: &[String],
    env_bindings: &[String],
    store: &SecretStore,
    mut out_writer: W1,
    mut err_writer: W2,
) -> Result<i32, String>
where
    W1: Write + Send + 'static,
    W2: Write + Send + 'static,
{
    if cmd.is_empty() {
        return Err("Missing command to execute".into());
    }
    let env = resolve_env_bindings(env_bindings, store)?;
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn '{}': {}", cmd[0], e))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let vault_dir_out = store.vault_dir.clone();
    let t_out = thread::spawn(move || {
        if let Some(s) = stdout {
            let local_store = SecretStore::new(Some(vault_dir_out), None);
            let mut reader = BufReader::new(s);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let clean = local_store
                    .redact_text(&line)
                    .unwrap_or_else(|_| line.clone());
                let _ = out_writer.write_all(clean.as_bytes());
                let _ = out_writer.flush();
                line.clear();
            }
        }
    });

    let vault_dir_err = store.vault_dir.clone();
    let t_err = thread::spawn(move || {
        if let Some(s) = stderr {
            let local_store = SecretStore::new(Some(vault_dir_err), None);
            let mut reader = BufReader::new(s);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let clean = local_store
                    .redact_text(&line)
                    .unwrap_or_else(|_| line.clone());
                let _ = err_writer.write_all(clean.as_bytes());
                let _ = err_writer.flush();
                line.clear();
            }
        }
    });

    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = t_out.join();
    let _ = t_err.join();
    Ok(status.code().unwrap_or(1))
}
