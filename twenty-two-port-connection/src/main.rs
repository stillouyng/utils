mod configs;
mod crypto;
mod structs;
mod types;

use crate::configs::{add_config, edit_config, list_configs, remove_config, run_config};
use crate::structs::{Cli, Command, EditArgs};
use clap::Parser;

fn main() {
    let cli = Cli::parse();

    match (&cli.name, &cli.command) {
        (Some(name), None) => {
            run_config(name);
        }
        (
            _,
            Some(Command::Add {
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
        (
            _,
            Some(Command::Edit {
                name,
                user,
                host,
                port,
                key,
                remove_key,
                password,
                remove_password,
            }),
        ) => {
            edit_config(
                name,
                EditArgs {
                    user: user.clone(),
                    host: host.clone(),
                    port: *port,
                    key: key.clone(),
                    remove_key: *remove_key,
                    with_password: *password,
                    remove_password: *remove_password,
                },
            );
        }
        (_, Some(Command::Remove { name })) => {
            remove_config(name);
        }
        (_, Some(Command::List {})) => {
            list_configs();
        }
        _ => {
            println!("Use 'twc <name>' or 'twc add <name> ...'")
        }
    }
}
