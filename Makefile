.PHONY: validate build fmt

validate:
	cargo fmt --check
	cargo clippy --all-targets --features linux-keychain -- -D warnings
	cargo test --features linux-keychain

build:
	cargo build --release --features linux-keychain

fmt:
	cargo fmt
