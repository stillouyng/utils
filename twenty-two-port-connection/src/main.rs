mod configs;
mod crypto;
mod structs;
mod types;

use crate::configs::{
    add_config, copy_config, copy_sp_config, edit_config, list_configs, remove_config,
    rename_config, run_config, show_config,
};
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
                sudo_password,
            }),
        ) => {
            add_config(
                name,
                user.clone(),
                host.clone(),
                *port,
                key.clone(),
                *password,
                *sudo_password,
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
                sudo_password,
                remove_sudo_password,
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
                    with_sudo_password: *sudo_password,
                    remove_sudo_password: *remove_sudo_password,
                },
            );
        }
        (_, Some(Command::Rename { name, new_name })) => {
            rename_config(name, new_name);
        }
        (_, Some(Command::Remove { name })) => {
            remove_config(name);
        }
        (_, Some(Command::List {})) => {
            list_configs();
        }
        (_, Some(Command::Show { name })) => {
            show_config(name);
        }
        (_, Some(Command::Copy { name })) => {
            copy_config(name);
        }
        (_, Some(Command::CopySp { name })) => {
            copy_sp_config(name);
        }
        _ => {
            println!("Use 'twc <name>' or 'twc add <name> ...'")
        }
    }
}
