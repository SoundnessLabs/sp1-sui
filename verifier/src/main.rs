use clap::Parser;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_sui::convert_sp1_gnark_to_ark;

/// CLI arguments
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the SP1 proof file
    #[arg(short, long, default_value = "../proofs/fibonacci_proof.bin")]
    proof_path: String,
}

fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Read the serialized SP1ProofWithPublicValues from the file.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&args.proof_path).unwrap();

    let (ark_groth16_serialized, ark_public_inputs_serialized, ark_proof_serialized) =
        convert_sp1_gnark_to_ark(sp1_proof_with_public_values);

    let ark_groth16_hex: String = hex::encode(ark_groth16_serialized);
    let ark_public_inputs_hex: String = hex::encode(ark_public_inputs_serialized);
    let ark_proof_hex: String = hex::encode(ark_proof_serialized);

    println!("\n=== Ark Groth16 Verification Components ===\n");

    println!("1. Verifying Key bytes:");
    println!("---------------------------");
    println!("{}\n", ark_groth16_hex);

    println!("2. Public Inputs bytes:");
    println!("---------------------------");
    println!("{}\n", ark_public_inputs_hex);

    println!("3. Proof bytes:");
    println!("---------------------------");
    println!("{}\n", ark_proof_hex);
}
