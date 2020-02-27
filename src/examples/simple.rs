use cryptography::pedersen_commitments::PedersenLabelGenerators;

fn main() {
    println!("Hello, world!");

    let plg = PedersenLabelGenerators::default();
    println!("{:?}", plg);
}
