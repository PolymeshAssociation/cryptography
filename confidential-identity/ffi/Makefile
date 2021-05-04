
gen:
	@cd ../../
	@cargo build --release
	@cd -
	@cbindgen --config cbindgen.toml --crate confidential-identity-ffi --output confidential_identity.h


build:
	@rm -f example.out
	@gcc examples/c_example.c -I include -L../../target/release/ -l confidential_identity_ffi -o example.out

run:
	@LD_LIBRARY_PATH=../../target/release ./example.out
