// opaq: binary entry point

use clap::Parser;

fn main() {
    let cli = opaq::cli::Cli::parse();
    if let Err(e) = opaq::cli::dispatch(cli) {
        eprintln!("Error: {e}");
        std::process::exit(e.exit_code());
    }
}
