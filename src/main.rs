use {
	std::process::exit,
	argh::FromArgs,
	onebm::*,
};

#[derive(FromArgs, PartialEq, Debug)]
/// 1bm: single binary manager
/// https://1bm.sh
///
struct CliArgs {
	#[argh(subcommand)]
	subcommand: Subcommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Subcommands {
	Install(SubcommandInstall),
	List(SubcommandList),
	Update(SubcommandUpdate),
	Uninstall(SubcommandUninstall),
}

#[derive(FromArgs, PartialEq, Debug)]
/// install binaries from specified dist files
#[argh(subcommand, name = "i")]
struct SubcommandInstall {
	#[argh(option)]
	/// optional custom binary name, no effect if multiple targets specified
	name: Option<String>,
	/// dist files, can be local path or URL
	#[argh(positional)]
	targets: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// list installed binaries
#[argh(subcommand, name = "ls")]
struct SubcommandList {}

#[derive(FromArgs, PartialEq, Debug)]
/// update binaries
#[argh(subcommand, name = "up")]
struct SubcommandUpdate {
	#[argh(positional)]
	binaries: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// uninstall binaries
#[argh(subcommand, name = "rm")]
struct SubcommandUninstall {
	#[argh(positional)]
	binaries: Vec<String>,
}

fn main() -> TResult<()> {
	let cli_args: CliArgs = argh::from_env();
	ensure_path();
	match cli_args.subcommand {
		Subcommands::Install(args) => {
			if args.targets.is_empty() {
				println!("No dist file specified.");
				exit(1);
			}
			if args.name.is_some() {
				if args.targets.len() != 1 {
					println!("Specifying custom binary name is not supported when installing multiple binaries.");
					exit(1);
				}
				let distfile = read_distfile(&args.targets[0])?;
				let name = args.name.unwrap();
				println!("Installing from dist file {}", args.targets[0]);
				install_binary(&distfile, Some(&name))?;
				println!("Installed binary {}", &name);
			} else {
				for target in args.targets {
					let distfile = read_distfile(&target)?;
					println!("Installing from dist file {}...", &target);
					let meta = install_binary(&distfile, None)?;
					println!("Installed as {}, version {}", meta.name, meta.version);
				}
			}
		},
		Subcommands::List(_) => {
			let list = read_binary_list()?;
			dbg!(list);
		},
		Subcommands::Update(args) => {
			let mut to_update = if args.binaries.is_empty() {
				read_binary_list()?
			} else {
				read_binary_list()?.iter()
					.filter(|meta| args.binaries.contains(&meta.name))
					.map(|meta| meta.to_owned()).collect()
			};

			if to_update.is_empty() {
				println!("Nothing to update.");
				exit(0);
			}

			for meta in to_update.iter_mut() {
				println!("Checking update for {}, current version {}", meta.name, meta.version);
				let (should_update, new_version) = check_update(meta)?;
				if should_update {
					println!("Updating {} to {}", meta.name, new_version);
					meta.version = new_version;
					update_binary(meta)?
				}
			}
		},
		Subcommands::Uninstall(args) => {
			if args.binaries.is_empty() {
				println!("No binary specified.");
				exit(1);
			}
			let binaries = read_binary_list()?;
			for meta in &binaries {
				if args.binaries.contains(&meta.name) {
					println!("Uninstalling {}", &meta.name);
					uninstall_binary(meta)?;
				}
			}
		},
	};
	Ok(())
}

