mod configs;
mod crypto;
mod structs;
mod types;

use crate::configs::{add_config, list_configs, remove_config, run_config};
use crate::structs::{Cli, Command};
use clap::Parser;

fn main() {
    let cli = Cli::parse();

    match (&cli.name, &cli.command) {
        (Some(name), None) => {
            run_config(name);
        }
        (
            _,
            Some(Command::AddConfig {
                name,
                user,
                host,
                port,
                key,
                password,
            }),
        ) => {
            add_config(
                name,
                user.clone(),
                host.clone(),
                *port,
                key.clone(),
                *password,
            );
        }
        (_, Some(Command::RemoveConfig { name })) => {
            remove_config(name);
        }
        (_, Some(Command::AllConfigs {})) => {
            list_configs();
        }
        _ => {
            println!("Use 'twc <name>' or 'twc add_config <name> ...'")
        }
    }
}
