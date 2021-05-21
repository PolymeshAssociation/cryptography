
gen:
	@echo "\e[31mMake sure to run 'make gen' inside cryptography/confidential_identity/ffi\e[0m\n"
	@cd ../../
	@cargo build --release
	@cd -
	@cbindgen --config cbindgen.toml --crate private-identity-audit-ffi --output include/private_identity_audit.h

build:
	@rm -f example.out
	@gcc examples/c_example.c -I include -I ../../confidential-identity/ffi -L../../target/release/ -l private_identity_audit_ffi -l confidential_identity_ffi -o example.out

run:
	@LD_LIBRARY_PATH=../../target/release ./example.out
