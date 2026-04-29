use crate::crypto::{decrypt, ecies_decrypt, ecies_encrypt, encrypt};
use crate::identity::{get_or_create_pubkey, get_pubkey_string, load_private_key, parse_pubkey};
use crate::structs::{EciesEnvelope, EditArgs, SSHConfig, ShareBlob};
use crate::types::ConfigMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::collections::HashMap;
use std::fs::{create_dir_all, read_to_string};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio, exit};
use zeroize::Zeroizing;

/// Parses a TTL string like `"30M"`, `"2H"`, `"7d"` into seconds.
/// Units: `s` seconds, `M` minutes, `H` hours, `d` days, `m` months (30d), `y` years (365d).
fn parse_ttl(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let n: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "M" => n * 60,
        "H" => n * 3600,
        "d" => n * 86400,
        "m" => n * 30 * 86400,
        "y" => n * 365 * 86400,
        _ => return None,
    };
    Some(secs)
}

/// Formats a duration in seconds as a human-readable string, e.g. `"2h 30m"`.
fn format_duration(mut secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    let years = secs / (365 * 86400);
    secs %= 365 * 86400;
    let days = secs / 86400;
    secs %= 86400;
    let hours = secs / 3600;
    secs %= 3600;
    let mins = secs / 60;
    let secs = secs % 60;

    let parts: Vec<String> = [
        (years, "y"),
        (days, "d"),
        (hours, "h"),
        (mins, "m"),
        (secs, "s"),
    ]
    .iter()
    .filter(|(v, _)| *v > 0)
    .take(2) // show at most two most-significant units
    .map(|(v, u)| format!("{v}{u}"))
    .collect();

    parts.join(" ")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_expired(cfg: &SSHConfig) -> bool {
    cfg.expires_at.is_some_and(|exp| unix_now() > exp)
}

const RESERVED_NAMES: &[&str] = &[
    "add",
    "remove",
    "list",
    "rename",
    "show",
    "edit",
    "copy",
    "copy-sp",
    "share-key",
    "help",
];

fn is_reserved(name: &str) -> bool {
    RESERVED_NAMES.contains(&name)
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .expect("Cannot find config directory")
        .join("twc")
        .join("config.json")
}

pub fn save_config(config: &ConfigMap) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        create_dir_all(dir)?;
    }
    let data = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn run_config(name: &str) {
    let config = load_config().unwrap_or_default();

    if let Some(cfg) = config.get(name) {
        if cfg.shared && is_expired(cfg) {
            let detail = cfg
                .expires_at
                .map(|exp| {
                    format!(
                        " (expired {} ago)",
                        format_duration(unix_now().saturating_sub(exp))
                    )
                })
                .unwrap_or_default();
            eprintln!("Shared profile '{name}' has expired{detail}.");
            eprintln!("Contact the sender for a fresh share, or remove it with: twc remove {name}");
            exit(1);
        }

        if let Some(ref encrypted) = cfg.password {
            // Prompt for master key, decrypt SSH password, use sshpass
            let master = Zeroizing::new(
                rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
            );
            // Used in the #[cfg(unix)] block below via the pipe.
            // On non-unix the code exits immediately before reaching it.
            #[cfg_attr(not(unix), allow(unused_variables))]
            let ssh_password = Zeroizing::new(match decrypt(encrypted, &master) {
                Some(p) => p,
                None => {
                    eprintln!("Wrong master key or corrupted data.");
                    exit(1);
                }
            });

            // Unix: feed the password through a pipe (-d fd) so it never
            // appears in /proc/<pid>/cmdline.
            // Windows: sshpass is unavailable regardless, so the -p path
            // is kept only to produce the "not found" error message.
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::io::FromRawFd;
                use std::os::unix::process::CommandExt;

                let mut pipe_fds = [0i32; 2];
                if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                    eprintln!("Failed to create password pipe.");
                    exit(1);
                }
                let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);

                // Write password to write end, then close it so sshpass sees EOF.
                {
                    let mut w = unsafe { std::fs::File::from_raw_fd(write_fd) };
                    w.write_all(ssh_password.as_bytes())
                        .expect("Failed to write password to pipe");
                }

                let mut cmd = ProcessCommand::new("sshpass");
                cmd.arg("-d").arg(read_fd.to_string());
                cmd.arg("ssh");
                cmd.arg(format!("{}@{}", cfg.user, cfg.host));
                if let Some(port) = cfg.port {
                    cmd.arg("-p").arg(format!("{port}"));
                }

                // Clear CLOEXEC on read_fd in the child so sshpass inherits it.
                unsafe {
                    cmd.pre_exec(move || {
                        let flags = libc::fcntl(read_fd, libc::F_GETFD, 0);
                        if flags == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }

                let mut child = match cmd
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        unsafe { libc::close(read_fd) };
                        eprintln!("Error: 'sshpass' not found.");
                        eprintln!(
                            "Install it with your package manager, e.g.: sudo apt install sshpass"
                        );
                        exit(1);
                    }
                    Err(e) => {
                        unsafe { libc::close(read_fd) };
                        eprintln!("Failed to start sshpass: {e}");
                        exit(1);
                    }
                };

                unsafe { libc::close(read_fd) };
                let status = child.wait().expect("sshpass failed");
                exit(status.code().unwrap_or(1));
            }

            #[cfg(not(unix))]
            {
                eprintln!("Error: password-based auth is not supported on Windows.");
                eprintln!("Use key-based auth (--key) instead.");
                exit(1);
            }
        } else {
            // Key-based or passwordless login
            let mut cmd = ProcessCommand::new("ssh");
            cmd.arg(format!("{}@{}", cfg.user, cfg.host));

            if let Some(port) = cfg.port {
                cmd.arg("-p").arg(format!("{port}"));
            }

            if let Some(ref key) = cfg.identity_file {
                cmd.arg("-i").arg(key);
            }

            let mut child = cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to start ssh");

            let status = child.wait().expect("SSH failed");
            exit(status.code().unwrap_or(1));
        }
    } else {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        exit(1);
    }
}

pub fn add_config(
    name: &str,
    user: String,
    host: String,
    port: Option<u16>,
    key: Option<String>,
    with_password: bool,
    with_sudo_password: bool,
) {
    if is_reserved(name) {
        eprintln!("'{name}' is a reserved command name and cannot be used as a profile name.");
        return;
    }
    if key.is_some() && with_password {
        eprintln!("Cannot use both --key and --password at the same time.");
        return;
    };
    let mut config = load_config().unwrap_or_default();

    let ssh_pass_plain: Option<Zeroizing<String>> = if with_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("SSH password: ").expect("Failed to read SSH password"),
        ))
    } else {
        None
    };
    let sudo_pass_plain: Option<Zeroizing<String>> = if with_sudo_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("Sudo password: ").expect("Failed to read sudo password"),
        ))
    } else {
        None
    };
    let master: Option<Zeroizing<String>> = if with_password || with_sudo_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
        ))
    } else {
        None
    };

    let encrypted_password = ssh_pass_plain.map(|p| encrypt(&p, master.as_deref().unwrap()));
    let encrypted_sudo_password = sudo_pass_plain.map(|p| encrypt(&p, master.as_deref().unwrap()));

    let ssh_config = SSHConfig {
        user,
        host,
        port,
        identity_file: key,
        password: encrypted_password,
        sudo_password: encrypted_sudo_password,
        shared: false,
        expires_at: None,
    };

    config.insert(name.to_string(), ssh_config);
    save_config(&config).expect("Failed to save config");
    println!("Added config '{}'.", name);
}

pub fn edit_config(name: &str, args: EditArgs) {
    if args.key.is_some() && args.remove_key {
        eprintln!("Cannot use both --key and --remove-key at the same time.");
        return;
    }
    if args.with_password && args.remove_password {
        eprintln!("Cannot use both --password and --remove-password at the same time.");
        return;
    }
    if args.with_sudo_password && args.remove_sudo_password {
        eprintln!("Cannot use both --sudo-password and --remove-sudo-password at the same time.");
        return;
    }

    let mut config = load_config().unwrap_or_default();

    let Some(cfg) = config.get_mut(name) else {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        return;
    };

    if cfg.shared {
        eprintln!("Cannot edit shared profile '{name}'.");
        eprintln!(
            "Shared profiles are read-only. Remove it and re-add manually if you need full control."
        );
        return;
    }

    if args.user.is_none()
        && args.host.is_none()
        && args.port.is_none()
        && args.key.is_none()
        && !args.remove_key
        && !args.with_password
        && !args.remove_password
        && !args.with_sudo_password
        && !args.remove_sudo_password
    {
        println!("Nothing to update.");
        return;
    }

    let will_have_key = (cfg.identity_file.is_some() && !args.remove_key) || args.key.is_some();
    let will_have_password =
        (cfg.password.is_some() && !args.remove_password) || args.with_password;

    if will_have_key && will_have_password {
        eprintln!("Conflict: profile would end up with both a key and a password.");
        eprintln!("Use --remove-key or --remove-password to resolve.");
        return;
    }

    if let Some(u) = args.user {
        cfg.user = u;
    }
    if let Some(h) = args.host {
        cfg.host = h;
    }
    if let Some(p) = args.port {
        cfg.port = Some(p);
    }

    if args.remove_key {
        cfg.identity_file = None;
    } else if let Some(k) = args.key {
        cfg.identity_file = Some(k);
    }

    let ssh_pass_plain: Option<Zeroizing<String>> = if args.with_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("SSH password: ").expect("Failed to read SSH password"),
        ))
    } else {
        None
    };
    let sudo_pass_plain: Option<Zeroizing<String>> = if args.with_sudo_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("Sudo password: ").expect("Failed to read sudo password"),
        ))
    } else {
        None
    };
    let master: Option<Zeroizing<String>> = if args.with_password || args.with_sudo_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
        ))
    } else {
        None
    };

    if args.remove_password {
        cfg.password = None;
    } else if let Some(p) = ssh_pass_plain {
        cfg.password = Some(encrypt(&p, master.as_deref().unwrap()));
    }

    if args.remove_sudo_password {
        cfg.sudo_password = None;
    } else if let Some(p) = sudo_pass_plain {
        cfg.sudo_password = Some(encrypt(&p, master.as_deref().unwrap()));
    }

    save_config(&config).expect("Failed to save config");
    println!("Updated config '{name}'.");
}

pub fn load_config() -> Result<ConfigMap, Box<dyn std::error::Error>> {
    let path = config_path();

    if let Some(dir) = path.parent() {
        create_dir_all(dir)?;
    }

    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data = read_to_string(path)?;

    let config = serde_json::from_str(&data).unwrap_or_default();

    Ok(config)
}

pub fn remove_config(name: &str) {
    let mut config = load_config().unwrap_or_default();

    if !config.contains_key(name) {
        eprintln!("No config named '{}' found.", name);
        return;
    }

    print!("Remove '{name}'? [y/N] ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    if input.trim().to_lowercase() != "y" {
        println!("Aborted.");
        return;
    }

    config.remove(name);
    save_config(&config).expect("Failed to save config");
    println!("Removed config '{}'.", name);
}

pub fn show_config(name: &str) {
    let config = load_config().unwrap_or_default();

    let Some(cfg) = config.get(name) else {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        exit(1);
    };

    let port = cfg
        .port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "22".to_string());
    let auth = if cfg.password.is_some() {
        "password".to_string()
    } else if let Some(ref key) = cfg.identity_file {
        format!("key ({})", key)
    } else {
        "passwordless".to_string()
    };
    let sudo = if cfg.sudo_password.is_some() {
        "Set"
    } else {
        "Unset"
    };

    println!("Name:  {name}");
    println!("User:  {}", cfg.user);
    println!("Host:  {}", cfg.host);
    println!("Port:  {port}");
    println!("Auth:  {auth}");
    println!("Sudo:  {sudo}");
    if cfg.shared {
        let expiry = match cfg.expires_at {
            None => "none".to_string(),
            Some(exp) => {
                let now = unix_now();
                if now > exp {
                    format!("expired {} ago", format_duration(now.saturating_sub(exp)))
                } else {
                    format!("in {}", format_duration(exp.saturating_sub(now)))
                }
            }
        };
        println!("Shared: yes (expires {expiry})");
    }
}

pub fn rename_config(name: &str, new_name: &str) {
    let mut config = load_config().unwrap_or_default();

    if !config.contains_key(name) {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        return;
    }

    if is_reserved(new_name) {
        eprintln!("'{new_name}' is a reserved command name and cannot be used as a profile name.");
        return;
    }

    if config.contains_key(new_name) {
        eprintln!("A profile named '{new_name}' already exists.");
        return;
    }

    let cfg = config.remove(name).unwrap();
    config.insert(new_name.to_string(), cfg);
    save_config(&config).expect("Failed to save config");
    println!("Renamed '{name}' to '{new_name}'.");
}

pub fn copy_config(name: &str, share: bool, for_key: Option<&str>, ttl: Option<&str>) {
    let config = load_config().unwrap_or_default();

    let Some(cfg) = config.get(name) else {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        exit(1);
    };

    if cfg.shared {
        eprintln!("Cannot copy credentials from shared profile '{name}'.");
        eprintln!("Shared profiles do not allow credential extraction or re-sharing.");
        exit(1);
    }

    if ttl.is_some() && !share {
        eprintln!("--ttl has no effect without --share.");
        exit(1);
    }

    if share {
        let recipient_key = for_key.unwrap_or_else(|| {
            eprintln!("--share requires --for-key <PUBKEY>.");
            eprintln!("The recipient can get their key with: twc share-key");
            exit(1);
        });
        share_config(name, cfg, recipient_key, ttl);
        return;
    }

    let port = cfg.port.unwrap_or(22);

    if let Some(ref encrypted) = cfg.password {
        let master = Zeroizing::new(
            rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
        );
        let ssh_password = Zeroizing::new(match decrypt(encrypted, &master) {
            Some(p) => p,
            None => {
                eprintln!("Wrong master key or corrupted data.");
                exit(1);
            }
        });

        let content = format!(
            "{}@{}:{} {}",
            cfg.user,
            cfg.host,
            port,
            ssh_password.as_str()
        );

        let mut clipboard = arboard::Clipboard::new().expect("Failed to access clipboard");
        clipboard
            .set_text(&content)
            .expect("Failed to copy to clipboard");

        println!(
            "Copied to clipboard: {}@{}:{} ***",
            cfg.user, cfg.host, port
        );
    } else if let Some(ref key) = cfg.identity_file {
        println!("Profile '{name}' uses key-based auth ({key}). No password to copy.");
        println!("Connection string: {}@{}:{}", cfg.user, cfg.host, port);
    } else {
        println!("Profile '{name}' uses passwordless auth. No password to copy.");
        println!("Connection string: {}@{}:{}", cfg.user, cfg.host, port);
    }
}

fn share_config(name: &str, cfg: &SSHConfig, recipient_key_str: &str, ttl: Option<&str>) {
    let recipient_pub = match parse_pubkey(recipient_key_str) {
        Some(k) => k,
        None => {
            eprintln!("Invalid recipient public key. Expected format: twc1:<base64>");
            exit(1);
        }
    };

    // Only prompt the master key if there are stored secrets to decrypt.
    let needs_master = cfg.password.is_some() || cfg.sudo_password.is_some();

    let (password_plain, sudo_password_plain) = if needs_master {
        let master = Zeroizing::new(
            rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
        );
        let pw = cfg.password.as_ref().map(|enc| {
            decrypt(enc, &master).unwrap_or_else(|| {
                eprintln!("Wrong master key or corrupted data.");
                exit(1);
            })
        });
        let spw = cfg.sudo_password.as_ref().map(|enc| {
            decrypt(enc, &master).unwrap_or_else(|| {
                eprintln!("Wrong master key or corrupted data.");
                exit(1);
            })
        });
        (pw, spw)
    } else {
        (None, None)
    };

    let key_bytes = if let Some(ref key_path) = cfg.identity_file {
        match std::fs::read(key_path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("Failed to read key file '{key_path}': {e}");
                exit(1);
            }
        }
    } else {
        None
    };

    let expires_at = if let Some(ttl_str) = ttl {
        match parse_ttl(ttl_str) {
            Some(secs) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("System clock is before Unix epoch")
                    .as_secs();
                Some(now + secs)
            }
            None => {
                eprintln!(
                    "Invalid TTL '{ttl_str}'. Use a number followed by a unit: \
                     30s, 15M, 2H, 7d, 1m, 1y"
                );
                exit(1);
            }
        }
    } else {
        None
    };

    let blob = ShareBlob {
        name: name.to_string(),
        user: cfg.user.clone(),
        host: cfg.host.clone(),
        port: cfg.port,
        password: password_plain,
        sudo_password: sudo_password_plain,
        key_bytes,
        expires_at,
    };

    let blob_json = Zeroizing::new(serde_json::to_string(&blob).expect("Serialization failed"));
    let envelope = ecies_encrypt(blob_json.as_bytes(), &recipient_pub);
    let envelope_json = serde_json::to_string(&envelope).expect("Serialization failed");
    // TWC3: signals a TTL-aware blob; old clients (which only accept TWC2:) will
    // reject it with a hard error instead of silently importing and ignoring expires_at.
    // Non-TTL blobs keep the TWC2: prefix so old clients can still import them.
    let prefix = if expires_at.is_some() { "TWC3" } else { "TWC2" };
    let clip_content = format!("{}:{}", prefix, B64.encode(envelope_json.as_bytes()));

    let mut clipboard = arboard::Clipboard::new().expect("Failed to access clipboard");
    clipboard
        .set_text(&clip_content)
        .expect("Failed to copy to clipboard");

    println!("Profile '{name}' encrypted for recipient and copied to clipboard.");
    if let Some(secs) = expires_at.map(|exp| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        exp.saturating_sub(now)
    }) {
        println!("Expires in: {}", format_duration(secs));
    }
    println!("Send the clipboard contents to the recipient.");
    println!("They can import it with: twc add --from-clip");
}

pub fn import_from_clip() {
    let mut clipboard = arboard::Clipboard::new().expect("Failed to access clipboard");
    let content = clipboard.get_text().expect("Failed to read clipboard");

    let trimmed = content.trim();
    let b64 = if let Some(s) = trimmed.strip_prefix("TWC3:") {
        s
    } else if let Some(s) = trimmed.strip_prefix("TWC2:") {
        s
    } else {
        eprintln!("Clipboard does not contain a valid twc share blob.");
        if trimmed.starts_with("TWC") {
            eprintln!("This blob uses a newer format — please update twc.");
        } else {
            eprintln!("Make sure the sender used: twc copy <name> --share --for-key <your-key>");
        }
        exit(1);
    };

    let envelope_json_bytes = match B64.decode(b64) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Invalid base64 in clipboard blob.");
            exit(1);
        }
    };

    let envelope_json = match String::from_utf8(envelope_json_bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Corrupted clipboard blob (invalid UTF-8).");
            exit(1);
        }
    };

    let envelope: EciesEnvelope = match serde_json::from_str(&envelope_json) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("Corrupted clipboard blob (cannot parse ECIES envelope).");
            exit(1);
        }
    };

    // Master key serves triple duty: decrypt identity private key, ECIES-decrypt
    // the blob, and re-encrypt the imported secrets under the recipient's key.
    let master = Zeroizing::new(
        rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
    );

    let priv_key = match load_private_key(&master) {
        Some(k) => k,
        None => {
            eprintln!("No identity key found. Run 'twc share-key' first to generate yours.");
            exit(1);
        }
    };

    let blob_json_bytes = match ecies_decrypt(&envelope, &priv_key) {
        Some(b) => b,
        None => {
            eprintln!("Decryption failed — wrong master key, wrong identity, or corrupted blob.");
            exit(1);
        }
    };

    let blob_json = Zeroizing::new(match String::from_utf8(blob_json_bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Corrupted blob content.");
            exit(1);
        }
    });

    let mut blob: ShareBlob = match serde_json::from_str(&*blob_json) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Failed to parse share blob.");
            exit(1);
        }
    };

    if let Some(expires_at) = blob.expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System clock is before Unix epoch")
            .as_secs();
        if now > expires_at {
            let expired_ago = format_duration(now.saturating_sub(expires_at));
            eprintln!("This share blob expired {expired_ago} ago and cannot be imported.");
            exit(1);
        }
        let remaining = format_duration(expires_at.saturating_sub(now));
        println!("(blob valid for {remaining} more)");
    }

    if is_reserved(&blob.name) {
        eprintln!(
            "'{}' is a reserved command name. Ask the sender to rename the profile.",
            blob.name
        );
        exit(1);
    }

    let mut config = load_config().unwrap_or_default();

    if config.contains_key(&blob.name) {
        eprintln!(
            "A profile named '{}' already exists. Remove it first with: twc remove {}",
            blob.name, blob.name
        );
        exit(1);
    }

    // Re-encrypt plaintext secrets under the recipient's own master key.
    // Use take() so the plaintext is moved out and the blob fields are cleared
    // before ZeroizeOnDrop runs on blob at end of scope.
    let encrypted_password = blob.password.take().map(|pw| encrypt(&pw, &master));
    let encrypted_sudo = blob.sudo_password.take().map(|pw| encrypt(&pw, &master));

    let identity_file = if let Some(key_bytes) = blob.key_bytes.take() {
        let ssh_dir = dirs::home_dir()
            .expect("Cannot find home directory")
            .join(".ssh");
        create_dir_all(&ssh_dir).expect("Cannot create ~/.ssh");

        let key_path = ssh_dir.join(format!("twc_{}", blob.name));
        std::fs::write(&key_path, &key_bytes).expect("Failed to write key file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("Failed to set key file permissions");
        }

        let key_path_str = key_path.to_string_lossy().to_string();
        println!("Private key written to: {key_path_str}");
        Some(key_path_str)
    } else {
        None
    };

    let ssh_config = SSHConfig {
        user: std::mem::take(&mut blob.user),
        host: std::mem::take(&mut blob.host),
        port: blob.port,
        identity_file,
        password: encrypted_password,
        sudo_password: encrypted_sudo,
        shared: true,
        expires_at: blob.expires_at,
    };

    let name = std::mem::take(&mut blob.name);
    config.insert(name.clone(), ssh_config);
    save_config(&config).expect("Failed to save config");
    println!("Imported profile '{name}'.");
}

/// Shows the user's twc public key and copies it to clipboard.
/// Auto-generates the X25519 keypair on first use (prompts for master key
/// to encrypt the stored private key).
pub fn show_share_key() {
    let pubkey = if let Some(pubkey) = get_pubkey_string() {
        pubkey
    } else {
        println!("No identity key found — generating one now.");
        let master = Zeroizing::new(
            rpassword::prompt_password("Master key (to protect your new identity key): ")
                .expect("Failed to read master key"),
        );
        let pubkey = get_or_create_pubkey(&master);
        println!("Your twc public key:");
        println!();
        println!("Share this with anyone who wants to send you a profile.");
        pubkey
    };

    println!("{pubkey}");

    match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&pubkey).map(|_| cb)) {
        Ok(_) => println!("(copied to clipboard)"),
        Err(e) => eprintln!("Warning: could not copy to clipboard: {e}"),
    }
}

pub fn list_configs() {
    let config = load_config().unwrap_or_default();

    if config.is_empty() {
        println!("No configs saved yet.");
        return;
    }

    let mut entries: Vec<_> = config.iter().collect();
    entries.sort_by_key(|(name, _)| name.as_str());

    for (name, cfg) in entries {
        let port = cfg.port.map(|p| format!(":{p}")).unwrap_or_default();
        let auth = if cfg.password.is_some() {
            "[password]"
        } else if cfg.identity_file.is_some() {
            "[key]"
        } else {
            "[passwordless]"
        };
        let sudo = if cfg.sudo_password.is_some() {
            " [sudo]"
        } else {
            ""
        };
        let shared_badge = if cfg.shared {
            if is_expired(cfg) {
                " [shared · expired]"
            } else {
                " [shared]"
            }
        } else {
            ""
        };
        println!(
            "{name} | {}@{}{port} {auth}{sudo}{shared_badge}",
            cfg.user, cfg.host
        );
    }
}

pub fn copy_sp_config(name: &str) {
    let config = load_config().unwrap_or_default();

    let Some(cfg) = config.get(name) else {
        eprintln!("No profile named '{name}' found. Run 'twc list' to see available profiles.");
        exit(1);
    };

    if cfg.shared {
        eprintln!("Cannot copy credentials from shared profile '{name}'.");
        eprintln!("Shared profiles do not allow credential extraction.");
        exit(1);
    }

    let Some(ref encrypted) = cfg.sudo_password else {
        eprintln!("Profile '{name}' has no sudo password stored.");
        eprintln!("Use 'twc edit {name} --sudo-password' to add one.");
        exit(1);
    };

    let master = Zeroizing::new(
        rpassword::prompt_password("Master key: ").expect("Failed to read master key"),
    );
    let sudo_password = Zeroizing::new(match decrypt(encrypted, &master) {
        Some(p) => p,
        None => {
            eprintln!("Wrong master key or corrupted data.");
            exit(1);
        }
    });

    let mut clipboard = arboard::Clipboard::new().expect("Failed to access clipboard");
    clipboard
        .set_text(sudo_password.as_str())
        .expect("Failed to copy to clipboard");

    println!("Sudo password for '{name}' copied to clipboard.");
}
