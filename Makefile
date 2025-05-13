TARGET_DIR = target

install-stwo:
	# NOTE: rust-toolchain.toml must be the same as the one in the stwo-cairo repo
	RUSTFLAGS="-C target-cpu=native -C opt-level=3" \
		cargo install \
		--git https://github.com/starkware-libs/stwo-cairo \
		--rev bde0d3a552c7280e27b3a249d85ee37ac55f642e \
		adapted_stwo

falcon-execute:
	rm -rf $(TARGET_DIR)/execute/falcon \
		&& cd packages/falcon \
		&& scarb execute --arguments-file tests/data/args_512_1.json --print-resource-usage

falcon-args:
	python packages/falcon/scripts/generate_args.py --n 512 --num_signatures 1 > packages/falcon/tests/data/args_512_1.json
	python packages/falcon/scripts/generate_args.py --n 1024 --num_signatures 1 > packages/falcon/tests/data/args_1024_1.json

falcon-build:
	scarb --profile release build --package falcon

falcon-cairo-execute:
	rm -rf $(TARGET_DIR)/execute/falcon \
		&& mkdir -p $(TARGET_DIR)/execute/falcon/execution1 \
		&& cairo-execute \
			--layout all_cairo \
			--args-file packages/falcon/tests/data/args_512_1.json \
			--standalone \
			--disable-trace-padding true \
			--prebuilt \
			--trace-file $(TARGET_DIR)/execute/falcon/execution1/trace.bin \
			--memory-file $(TARGET_DIR)/execute/falcon/execution1/memory.bin \
			--air-public-input $(TARGET_DIR)/execute/falcon/execution1/air_public_input.json \
			--air-private-input $(TARGET_DIR)/execute/falcon/execution1/air_private_input.json \
			$(TARGET_DIR)/release/falcon.executable.json

falcon-prove:
	adapted_stwo \
		--priv_json $(TARGET_DIR)/execute/falcon/execution1/air_private_input.json \
		--pub_json $(TARGET_DIR)/execute/falcon/execution1/air_public_input.json \
		--proof_path $(TARGET_DIR)/proof.json \
		--params_json prover_params.json \
		--verify

falcon-burn:
	scarb burn --package falcon --arguments-file packages/falcon/tests/data/args_512_1.json --output-file target/falcon.svg --open-in-browser
