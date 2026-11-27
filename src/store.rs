use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    v: u8,
    salt: String,
    nonce: String,
    ct: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    pub target: String,
    pub headers: BTreeMap<String, String>,
}

pub struct SecretStore {
    pub vault_dir: PathBuf,
    vault_file: PathBuf,
    key_file: PathBuf,
    routes_file: PathBuf,
    passphrase: Option<Zeroizing<String>>,
}

impl SecretStore {
    pub fn new(vault_dir: Option<PathBuf>, passphrase: Option<String>) -> Self {
        let dir = vault_dir.unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".agent-vault")
        });
        Self {
            vault_file: dir.join("vault.enc"),
            key_file: dir.join("master.key"),
            routes_file: dir.join("routes.json"),
            vault_dir: dir,
            passphrase: passphrase.map(Zeroizing::new),
        }
    }

    fn ensure_dir(&self) -> Result<(), String> {
        fs::create_dir_all(&self.vault_dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.vault_dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    fn master_secret(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        if let Some(ref p) = self.passphrase {
            return Ok(Zeroizing::new(p.as_bytes().to_vec()));
        }
        if let Ok(env_key) = std::env::var("AGENT_VAULT_KEY") {
            if !env_key.is_empty() {
                return Ok(Zeroizing::new(env_key.into_bytes()));
            }
        }
        self.ensure_dir()?;
        if !self.key_file.is_file() {
            let mut raw = Zeroizing::new([0u8; 32]);
            rand::thread_rng().fill_bytes(&mut *raw);
            let encoded = Zeroizing::new(B64.encode(*raw));
            fs::write(&self.key_file, encoded.as_bytes()).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.key_file, fs::Permissions::from_mode(0o600));
            }
        }
        let bytes = fs::read(&self.key_file).map_err(|e| e.to_string())?;
        let trimmed = bytes
            .into_iter()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        Ok(Zeroizing::new(trimmed))
    }

    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let master = self.master_secret()?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(&master, salt, &mut *out)
            .map_err(|e| format!("Key derivation failed: {}", e))?;
        Ok(out)
    }

    fn load_all(&self) -> Result<BTreeMap<String, Zeroizing<String>>, String> {
        if !self.vault_file.is_file() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&self.vault_file).map_err(|e| e.to_string())?;
        let blob: VaultBlob = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let salt = B64.decode(&blob.salt).map_err(|e| e.to_string())?;
        let nonce_bytes = B64.decode(&blob.nonce).map_err(|e| e.to_string())?;
        let ct = B64.decode(&blob.ct).map_err(|e| e.to_string())?;

        if nonce_bytes.len() != 24 {
            return Err("Invalid nonce length in vault".into());
        }
        let key = self.derive_key(&salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|e| e.to_string())?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let pt = Zeroizing::new(
            cipher
                .decrypt(nonce, ct.as_ref())
                .map_err(|_| "Vault decryption/authentication failed".to_string())?,
        );
        let map: BTreeMap<String, String> =
            serde_json::from_slice(&pt).map_err(|e| e.to_string())?;
        Ok(map
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect())
    }

    fn save_all(&self, data: &BTreeMap<String, Zeroizing<String>>) -> Result<(), String> {
        self.ensure_dir()?;
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = self.derive_key(&salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|e| e.to_string())?;
        let plain_map: BTreeMap<&str, &str> =
            data.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let pt = Zeroizing::new(serde_json::to_vec(&plain_map).map_err(|e| e.to_string())?);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, pt.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let blob = VaultBlob {
            v: 1,
            salt: B64.encode(salt),
            nonce: B64.encode(nonce_bytes),
            ct: B64.encode(ct),
        };
        let serialized = serde_json::to_string_pretty(&blob).map_err(|e| e.to_string())? + "\n";
        fs::write(&self.vault_file, serialized).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.vault_file, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn set_secret(&self, name: &str, value: &str) -> Result<(), String> {
        validate_secret_name(name)?;
        let mut data = self.load_all()?;
        data.insert(name.to_string(), Zeroizing::new(value.to_string()));
        self.save_all(&data)
    }

    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        let mut data = self.load_all()?;
        Ok(data.remove(name))
    }

    pub fn delete_secret(&self, name: &str) -> Result<bool, String> {
        let mut data = self.load_all()?;
        let existed = data.remove(name).is_some();
        if existed {
            self.save_all(&data)?;
        }
        Ok(existed)
    }

    pub fn list_secrets(&self) -> Result<Vec<(String, String)>, String> {
        let data = self.load_all()?;
        let mut out = Vec::with_capacity(data.len());
        for (k, v) in data {
            let preview = if v.chars().count() > 6 {
                format!("{}****", v.chars().take(4).collect::<String>())
            } else {
                "****".to_string()
            };
            out.push((k, preview));
        }
        Ok(out)
    }

    /// Redact raw, Base64-encoded, and URL-encoded forms of every stored secret.
    pub fn redact_text(&self, text: &str) -> Result<String, String> {
        if text.is_empty() {
            return Ok(String::new());
        }
        let data = self.load_all()?;
        let mut pairs: Vec<(String, Zeroizing<String>)> = data.into_iter().collect();
        pairs.sort_by_key(|a| std::cmp::Reverse(a.1.len()));

        let mut out = text.to_string();
        for (name, val) in pairs {
            if val.len() < 4 {
                continue;
            }
            let tag = format!("[REDACTED:{}]", name);
            if out.contains(val.as_str()) {
                out = out.replace(val.as_str(), &tag);
            }
            let b64 = Zeroizing::new(B64.encode(val.as_bytes()));
            if b64.len() >= 6 && out.contains(b64.as_str()) {
                out = out.replace(b64.as_str(), &tag);
            }
            let urlenc = Zeroizing::new(percent_encode(val.as_str()));
            if urlenc.as_str() != val.as_str() && out.contains(urlenc.as_str()) {
                out = out.replace(urlenc.as_str(), &tag);
            }
        }
        Ok(out)
    }

    pub fn load_routes(&self) -> Result<HashMap<String, RouteConfig>, String> {
        if !self.routes_file.is_file() {
            return Ok(HashMap::new());
        }
        let raw = fs::read_to_string(&self.routes_file).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    }

    pub fn save_route(
        &self,
        name: &str,
        target_base: &str,
        headers: BTreeMap<String, String>,
        allow_insecure_http: bool,
    ) -> Result<(), String> {
        validate_route_name(name)?;
        validate_upstream_url(target_base, allow_insecure_http)?;
        self.ensure_dir()?;
        let mut routes = self.load_routes()?;
        routes.insert(
            name.to_string(),
            RouteConfig {
                target: target_base.trim_end_matches('/').to_string(),
                headers,
            },
        );
        let text = serde_json::to_string_pretty(&routes).map_err(|e| e.to_string())? + "\n";
        fs::write(&self.routes_file, text).map_err(|e| e.to_string())
    }
}

pub fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(format!("Invalid secret name '{}'", name));
    }
    Ok(())
}

pub fn validate_route_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("Invalid route name '{}'", name));
    }
    Ok(())
}

pub fn validate_upstream_url(url: &str, allow_insecure_http: bool) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("http://[::1]")
    {
        return Ok(());
    }
    if allow_insecure_http && lower.starts_with("http://") {
        return Ok(());
    }
    Err(
        "Upstream URL must use https:// (or localhost/127.0.0.1, or pass --allow-insecure-http)"
            .into(),
    )
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
