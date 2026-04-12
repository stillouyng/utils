use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Debug, Subcommand)]
pub enum Command {
    #[clap(
        name = "add",
        about = "Add a new SSH config profile",
        long_about = "Add a new SSH config profile.

        Examples:
          twc add myserver alice 192.168.1.1
          twc add myserver alice 192.168.1.1 --port 2222
          twc add myserver alice 192.168.1.1 --key ~/.ssh/id_rsa
          twc add myserver alice 192.168.1.1 --password   (prompts for SSH password + master key)
        "
    )]
    Add {
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
        name = "remove",
        about = "Remove an existing SSH config profile",
        long_about = "Remove an existing SSH config profile by name.

        Example:
          twc remove myserver
        "
    )]
    Remove { name: String },
    #[clap(
        name = "list",
        about = "List all config profiles",
        long_about = "List all config profiles in format: {name} | {user}@{host}:{port} [password | key]"
    )]
    List {},
    #[clap(
        name = "edit",
        about = "Edit an existing SSH config profile",
        long_about = "Edit fields of an existing SSH profile. Only specified flags are updated.

        Examples:
          twc edit myserver --host new.host.com
          twc edit myserver --port 2222 --key ~/.ssh/id_ed25519
          twc edit myserver --remove-key --password
          twc edit myserver --remove-password --password
        "
    )]
    Edit {
        name: String,
        #[clap(long, help = "New SSH user")]
        user: Option<String>,
        #[clap(long, help = "New SSH host")]
        host: Option<String>,
        #[clap(long, help = "New SSH port")]
        port: Option<u16>,
        #[clap(long, help = "New path to private key file")]
        key: Option<String>,
        #[clap(long, help = "Remove the stored private key")]
        remove_key: bool,
        #[clap(
            long,
            help = "Set or change the encrypted SSH password (you will be prompted)"
        )]
        password: bool,
        #[clap(long, help = "Remove the stored SSH password")]
        remove_password: bool,
    },
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
      twc add <name> <user> <host> [options]    Save a new SSH profile
      twc remove <name>                         Delete a saved profile

    Examples:
      twc add prod deploy 10.0.0.1 --password
      twc add staging alice staging.example.com --port 2222 --key ~/.ssh/id_ed25519
      twc prod
      twc remove prod
    "
)]
pub struct Cli {
    pub name: Option<String>,
    #[clap(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug)]
pub struct EditArgs {
    pub user: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub key: Option<String>,
    pub remove_key: bool,
    pub with_password: bool,
    pub remove_password: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSHConfig {
    pub user: String,
    pub host: String,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default, alias = "indentify_file")]
    pub identity_file: Option<String>,

    #[serde(default)]
    pub password: Option<EncryptedSecret>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecret {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
