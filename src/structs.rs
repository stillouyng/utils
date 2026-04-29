use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

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
          twc add --from-clip                                  (import a shared profile from clipboard)
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
          twc copy myserver --share --for-key twc1:<pubkey>
          twc copy myserver --share --for-key twc1:<pubkey> --ttl 24H
        "
    )]
    Copy {
        name: String,
        #[clap(
            long,
            help = "Generate a portable shareable blob encrypted for the recipient"
        )]
        share: bool,
        #[clap(
            long,
            value_name = "PUBKEY",
            help = "Recipient's twc public key (required with --share). Get it with: twc share-key"
        )]
        for_key: Option<String>,
        #[clap(
            long,
            value_name = "DURATION",
            help = "Blob expiry, e.g. 30s, 15M, 2H, 7d, 1m, 1y (requires --share)"
        )]
        ttl: Option<String>,
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
        name = "share-key",
        about = "Show your twc public key for receiving shared profiles",
        long_about = "Display your twc public key so others can encrypt profiles for you.

        The X25519 keypair is generated automatically on first use and the private
        key is stored encrypted (Argon2 + AES-256-GCM) under your master key.

        Share the printed key with anyone who wants to send you a profile via
        'twc copy <name> --share --for <your-key>'.

        Example:
          twc share-key
        "
    )]
    ShareKey {},
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
      twc <name>                                Connect using a saved profile
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

    #[serde(default)]
    pub identity_file: Option<String>,

    #[serde(default)]
    pub password: Option<EncryptedSecret>,

    #[serde(default)]
    pub sudo_password: Option<EncryptedSecret>,

    #[serde(default)]
    pub shared: bool,

    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecret {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// ECIES envelope produced by `twc copy --share`.
///
/// Contains an ephemeral X25519 public key and an AES-256-GCM ciphertext whose
/// plaintext is the JSON-serialised [`ShareBlob`].  The AES key is derived via
/// HKDF-SHA256 from the X25519 shared secret.
///
/// Serialised to JSON, base64-encoded, and placed on the clipboard as
/// `TWC2:<base64>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EciesEnvelope {
    /// Sender's ephemeral X25519 public key (32 bytes).
    pub eph_pub: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// Encrypted [`ShareBlob`] JSON.
    pub ciphertext: Vec<u8>,
}

/// Portable profile blob — the plaintext inside an [`EciesEnvelope`].
///
/// Secrets travel as **plaintext** inside the blob; they are protected
/// exclusively by the ECIES outer encryption.  On import the recipient
/// re-encrypts them under their own master key before writing to disk —
/// the sender's master key never leaves the sender's machine.
///
/// `expires_at` is a Unix timestamp (seconds).  Because it lives in the
/// authenticated plaintext, AES-256-GCM makes it tamper-proof — nobody
/// can extend the TTL without the recipient's private key.
#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ShareBlob {
    pub name: String,
    pub user: String,
    pub host: String,
    pub port: Option<u16>,
    /// Plaintext SSH password (only present for password-auth profiles).
    pub password: Option<String>,
    /// Plaintext sudo password.
    pub sudo_password: Option<String>,
    /// Raw private key file bytes for key-based profiles.  Written to
    /// `~/.ssh/twc_<name>` on the recipient's machine by `--from-clip`.
    pub key_bytes: Option<Vec<u8>>,
    /// Optional expiry as a Unix timestamp.  `twc add --from-clip` rejects
    /// the blob if `now > expires_at`.
    pub expires_at: Option<u64>,
}
