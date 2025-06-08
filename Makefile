TARGET_DIR = target

install-cairo-prove:
	RUSTFLAGS="-C target-cpu=native -C opt-level=3" \
		cargo install \
			--git https://github.com/starkware-libs/stwo-cairo \
			--rev adc68829b0e913d5a8bdf14932a45fde27a2e335 \
			cairo-prove

falcon-execute:
	rm -rf $(TARGET_DIR)/execute/falcon \
		&& cd packages/falcon \
		&& scarb execute --arguments-file tests/data/args_512_1.json --print-resource-usage

falcon-args:
	python packages/falcon/scripts/generate_args.py --n 512 --num_signatures 1 > packages/falcon/tests/data/args_512_1.json
	python packages/falcon/scripts/generate_args.py --n 1024 --num_signatures 1 > packages/falcon/tests/data/args_1024_1.json

falcon-build:
	scarb --profile release build --package falcon

falcon-prove: falcon-build
	rm -rf $(TARGET_DIR)/execute/falcon
	mkdir -p $(TARGET_DIR)/execute/falcon
	cairo-prove prove \
		$(TARGET_DIR)/release/falcon.executable.json \
		$(TARGET_DIR)/execute/falcon/proof.json \
		--arguments-file packages/falcon/tests/data/args_512_1.json \
		--proof-format cairo-serde

falcon-burn:
	scarb burn --package falcon \
		--arguments-file packages/falcon/tests/data/args_512_1.json \
		--output-file target/falcon.svg \
		--open-in-browser

sphincs-build:
	scarb --profile release build --package sphincs_plus --features blake_hash,sparse_addr

sphincs-execute: sphincs-build
	rm -rf $(TARGET_DIR)/execute/sphincs_plus
	scarb --profile release execute \
		--no-build \
		--package sphincs_plus \
		--print-resource-usage \
		--arguments-file packages/sphincs-plus/tests/data/sha2_simple_128s.json

sphincs-burn: sphincs-build
	scarb burn --package sphincs_plus \
		--no-build \
		--output-file target/sphincs-plus.svg \
		--arguments-file packages/sphincs-plus/tests/data/sha2_simple_128s.json \
		--open-in-browser

sphincs-prove: sphincs-build
	rm -rf $(TARGET_DIR)/execute/sphincs_plus
	mkdir -p $(TARGET_DIR)/execute/sphincs_plus
	cairo-prove prove \
		$(TARGET_DIR)/release/sphincs_plus.executable.json \
		$(TARGET_DIR)/execute/sphincs_plus/proof.json \
		--arguments-file packages/sphincs-plus/tests/data/sha2_simple_128s.json \
		--proof-format cairo-serde
