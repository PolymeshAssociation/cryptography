use cryptography::pedersen_commitments::PedersenGenerators;

fn main() {
    println!("Hello, world!");

    let plg = PedersenGenerators::default();
    println!("{:?}", plg);
}
