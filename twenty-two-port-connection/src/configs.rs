use crate::crypto::{decrypt, encrypt};
use crate::structs::SSHConfig;
use crate::types::ConfigMap;
use std::collections::HashMap;
use std::fs::{create_dir_all, read_to_string};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio, exit};

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
    std::fs::write(path, data)?;
    Ok(())
}

pub fn run_config(name: &str) {
    let config = load_config().unwrap_or_default();

    if let Some(cfg) = config.get(name) {
        if let Some(ref encrypted) = cfg.password {
            // Prompt for master key, decrypt SSH password, use sshpass
            let master =
                rpassword::prompt_password("Master key: ").expect("Failed to read master key");

            let ssh_password = match decrypt(encrypted, &master) {
                Some(p) => p,
                None => {
                    eprintln!("Wrong master key or corrupted data.");
                    exit(1);
                }
            };

            let mut cmd = ProcessCommand::new("sshpass");
            cmd.arg("-p").arg(&ssh_password);
            cmd.arg("ssh");
            cmd.arg(format!("{}@{}", cfg.user, cfg.host));

            if let Some(port) = cfg.port {
                cmd.arg("-p").arg(format!("{port}"));
            }

            let mut child = match cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("Error: 'sshpass' not found.");
                    #[cfg(target_os = "windows")]
                    eprintln!(
                        "sshpass is not available on Windows. Use key-based auth (--key) instead."
                    );
                    #[cfg(not(target_os = "windows"))]
                    eprintln!(
                        "Install it with your package manager, e.g.: sudo apt install sshpass"
                    );
                    exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to start sshpass: {e}");
                    exit(1);
                }
            };

            let status = child.wait().expect("sshpass failed");
            exit(status.code().unwrap_or(1));
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
) {
    if key.is_some() && with_password {
        eprintln!("Cannot use both --key and --password at the same time.");
        return;
    };
    let mut config = load_config().unwrap_or_default();

    let encrypted_password = if with_password {
        let ssh_pass =
            rpassword::prompt_password("SSH password: ").expect("Failed to read SSH password");
        let master = rpassword::prompt_password("Master key: ").expect("Failed to read master key");
        Some(encrypt(&ssh_pass, &master))
    } else {
        None
    };

    let ssh_config = SSHConfig {
        user,
        host,
        port,
        identity_file: key,
        password: encrypted_password,
    };

    config.insert(name.to_string(), ssh_config);
    save_config(&config).expect("Failed to save config");
    println!("Added config '{}'.", name);
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
        println!("{name} | {}@{}{port} {auth}", cfg.user, cfg.host);
    }
}
