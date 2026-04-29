mod configs;
mod crypto;
mod identity;
mod structs;
mod types;

use crate::configs::{
    add_config, copy_config, copy_sp_config, edit_config, import_from_clip, list_configs,
    remove_config, rename_config, run_config, scp_config, show_config, show_share_key,
};
use crate::structs::{Cli, Command, EditArgs};
use clap::Parser;
use std::process::exit;

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
                from_clip,
            }),
        ) => {
            if *from_clip {
                import_from_clip();
            } else {
                let name = name.as_deref().unwrap_or_else(|| {
                    eprintln!("error: 'name' is required (omit only when using --from-clip)");
                    exit(1);
                });
                let user = user.clone().unwrap_or_else(|| {
                    eprintln!("error: 'user' is required (omit only when using --from-clip)");
                    exit(1);
                });
                let host = host.clone().unwrap_or_else(|| {
                    eprintln!("error: 'host' is required (omit only when using --from-clip)");
                    exit(1);
                });
                add_config(
                    name,
                    user,
                    host,
                    *port,
                    key.clone(),
                    *password,
                    *sudo_password,
                );
            }
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
        (
            _,
            Some(Command::Copy {
                name,
                share,
                for_key,
                ttl,
            }),
        ) => {
            copy_config(name, *share, for_key.as_deref(), ttl.as_deref());
        }
        (_, Some(Command::ShareKey {})) => {
            show_share_key();
        }
        (_, Some(Command::CopySp { name })) => {
            copy_sp_config(name);
        }
        (
            _,
            Some(Command::Scp {
                name,
                src,
                dst,
                from_local,
            }),
        ) => {
            scp_config(name, src, dst, *from_local);
        }
        _ => {
            println!("Use 'twc <name>' or 'twc add <name> ...'")
        }
    }
}
