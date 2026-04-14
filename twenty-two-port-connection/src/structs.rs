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
          twc add myserver alice 192.168.1.1 --password        (prompts for SSH password + master key)
          twc add myserver alice 192.168.1.1 --sudo-password   (prompts for sudo password + master key)
          twc add --from-clip                                   (import a shared profile from clipboard)
        "
    )]
    Add {
        name: Option<String>,
        user: Option<String>,
        host: Option<String>,
        #[clap(long, help = "SSH port (default: 22)")]
        port: Option<u16>,
        #[clap(long, help = "Path to private key file")]
        key: Option<String>,
        #[clap(
            long,
            help = "Store an encrypted SSH password (you will be prompted for the password and a master key)"
        )]
        password: bool,
        #[clap(
            long,
            help = "Store an encrypted sudo password (you will be prompted for the password and a master key)"
        )]
        sudo_password: bool,
        #[clap(
            long,
            help = "Import a profile from a twc share blob in clipboard (name/user/host are not required)"
        )]
        from_clip: bool,
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
        long_about = "List all config profiles in format: {name} | {user}@{host}:{port} [password | key] [sudo]"
    )]
    List {},
    #[clap(
        name = "rename",
        about = "Rename an existing SSH config profile",
        long_about = "Rename a saved SSH profile without changing any of its fields.

        Example:
          twc rename myserver prod
        "
    )]
    Rename { name: String, new_name: String },
    #[clap(
        name = "show",
        about = "Show details of a single SSH config profile",
        long_about = "Show all fields of a saved SSH profile.

        Example:
          twc show myserver
        "
    )]
    Show { name: String },
    #[clap(
        name = "copy",
        about = "Copy SSH connection info to clipboard",
        long_about = "Copy SSH connection info to clipboard.

        For password-protected profiles, prompts for the master key, decrypts the SSH password,
        and copies 'user@host:port password' to clipboard. The password is hidden in console output.

        For key-based or passwordless profiles, prints the connection string to console — there is
        no credential to copy.

        Examples:
          twc copy myserver
          twc copy myserver --share   (generates a portable blob and copies it to clipboard)
        "
    )]
    Copy {
        name: String,
        #[clap(
            long,
            help = "Generate a portable shareable blob and copy it to clipboard for import on another machine"
        )]
        share: bool,
    },
    #[clap(
        name = "edit",
        about = "Edit an existing SSH config profile",
        long_about = "Edit fields of an existing SSH profile. Only specified flags are updated.

        Examples:
          twc edit myserver --host new.host.com
          twc edit myserver --port 2222 --key ~/.ssh/id_ed25519
          twc edit myserver --remove-key --password
          twc edit myserver --remove-password --password
          twc edit myserver --sudo-password
          twc edit myserver --remove-sudo-password
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
        #[clap(
            long,
            help = "Set or change the encrypted sudo password (you will be prompted)"
        )]
        sudo_password: bool,
        #[clap(long, help = "Remove the stored sudo password")]
        remove_sudo_password: bool,
    },
    #[clap(
        name = "copy-sp",
        about = "Copy the sudo password for a profile to clipboard",
        long_about = "Prompts for the master key, decrypts the stored sudo password, and copies it
        to clipboard. The password is hidden in console output.

        Example:
          twc copy-sp myserver
        "
    )]
    CopySp { name: String },
}

#[derive(Debug, Parser)]
#[clap(
    name = "twc",
    version,
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
    pub with_sudo_password: bool,
    pub remove_sudo_password: bool,
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

    #[serde(default)]
    pub sudo_password: Option<EncryptedSecret>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecret {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Portable profile blob used by `twc copy --share` / `twc add --from-clip`.
///
/// The whole struct is serialised to JSON, encrypted with AES-256-GCM
/// (using the sender's master key), and the resulting [`EncryptedSecret`] is
/// JSON-encoded then base64-encoded before being placed on the clipboard as
/// `TWC1:<base64>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShareBlob {
    pub name: String,
    pub user: String,
    pub host: String,
    pub port: Option<u16>,
    /// Already-encrypted SSH password (travels as-is; recipient must use the
    /// same master key to decrypt it later).
    pub password: Option<EncryptedSecret>,
    /// Already-encrypted sudo password (same note as above).
    pub sudo_password: Option<EncryptedSecret>,
    /// Raw private key file bytes for key-based profiles.  Written to
    /// `~/.ssh/twc_<name>` on the recipient's machine by `--from-clip`.
    pub key_bytes: Option<Vec<u8>>,
}
