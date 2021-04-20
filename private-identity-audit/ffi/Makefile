LIB_DIR_LOCAL=-L../../target/release
LIB=-l private_identity_audit_ffi

gen:
	@cd ../../
	@cargo build --release
	@cd -
	@cbindgen --config cbindgen.toml --crate private-identity-audit-ffi --output include/private_identity_audit.h --lang c

build:
	@gcc examples/c_example.c -I include $(LIB_DIR_LOCAL) $(LIB) -o example.out

run:
	@LD_LIBRARY_PATH=../../target/release ./example.out
