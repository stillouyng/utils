use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Debug, Subcommand)]
pub enum Command {
    #[clap(
        name = "add_config",
        about = "Add a new SSH config profile",
        long_about = "Add a new SSH config profile.

        Examples:
          twc add_config myserver alice 192.168.1.1
          twc add_config myserver alice 192.168.1.1 --port 2222
          twc add_config myserver alice 192.168.1.1 --key ~/.ssh/id_rsa
          twc add_config myserver alice 192.168.1.1 --password   (prompts for SSH password + master key)
        "
    )]
    AddConfig {
        name: String,
        user: String,
        host: String,
        #[clap(long, help = "SSH port (default: 22)")]
        port: Option<u16>,
        #[clap(long, help = "Path to private key file")]
        key: Option<String>,
        #[clap(
            long,
            help = "Store an encrypted SSH password (you will be prompted for the password and a master key)"
        )]
        password: bool,
    },
    #[clap(
        name = "remove_config",
        about = "Remove an existing SSH config profile",
        long_about = "Remove an existing SSH config profile by name.

        Example:
          twc remove_config myserver
        "
    )]
    RemoveConfig { name: String },
    #[clap(
        name = "all_configs",
        about = "List all config profiles",
        long_about = "List all config profiles in format: {name} | {user}@{host}:{port}"
    )]
    AllConfigs {},
}

#[derive(Debug, Parser)]
#[clap(
    name = "twc",
    about = "Tiny wrapper for SSH connections",
    long_about = "twc — a tiny SSH connection manager.

    Stores SSH profiles locally and connects with a single command.
    Passwords are encrypted with AES-256-GCM and protected by a master key.
    Usage:
      twc <name>                                       Connect using a saved profile
      twc add_config <name> <user> <host> [options]    Save a new SSH profile
      twc remove_config <name>                         Delete a saved profile\n\nOptions for add_config:
        --port <PORT>                   SSH port (default: 22)
        --key <PATH>                    Path to private key file
        --password                      Prompt for SSH password (encrypted with master key)

    Examples:
      twc add_config prod deploy 10.0.0.1 --password
      twc add_config staging alice staging.example.com --port 2222 --key ~/.ssh/id_ed25519
      twc prod
      twc remove_config prod
    "
)]
pub struct Cli {
    pub name: Option<String>,
    #[clap(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSHConfig {
    pub user: String,
    pub host: String,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub identify_file: Option<String>,

    #[serde(default)]
    pub password: Option<EncryptedSecret>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecret {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
