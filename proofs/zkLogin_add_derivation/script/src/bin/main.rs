//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use zklogin_lib::PublicValuesStruct;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKLOGIN_ELF: &[u8] = include_elf!("zkLogin_address_derivation");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "https://accounts.google.com")]
    iss: &str,

    #[clap(long, default_value = "206703048842351542647799591018316385612")]
    salt: &str,

    #[clap(long, default_value = "sub")]
    name: &str,  // i.e. "sub"
    
    #[clap(long, default_value = "106294049240999307923")]
    value: &str, // i.e. the sub value
    
    #[clap(long, default_value = "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com")]
    aud: &str,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
   
    stdin.write(&args.iss);
    stdin.write(&args.salt);
    stdin.write(&args.name);
    stdin.write(&args.value);
    stdin.write(&args.aud);

    println!("iss: {}", args.iss);
    println!("salt: {}", args.salt);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(ZKLOGIN_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct { iss, salt, name, value, aud, address_seed, zkLogin_address } = decoded;
        println!("zkLogin_address: {}", zkLogin_address);

        let (expected_address) = zklogin_lib::get_zk_login_address(address_seed, iss);
        assert_eq!(zkLogin_address, expected_address);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        // zk_login_address = Blake2b256(len(iss) || iss || poseidon_zk_login(name, value, aud, poseidon_zk_login(salt))
    
        let (pk, vk) = client.setup(ZKLOGIN_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
