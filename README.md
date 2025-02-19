# `sp1-sui` - SP1 Verifier on Sui

![SP1 Sui Banner](banner.png)

This crate verifies Groth16 proofs generated by [SP1 zkVM](https://github.com/succinctlabs/sp1) in Sui Move smart contract leveraging the Groth16 Move verifier over BN254.

> [!CAUTION]
>
> This repository is not audited for production use.

## Repository Overview

- The `sp1-sui` library is located in the [`verifier`](verifier) directory. 
- The [`proofs`](proofs) directory includes the [Fibonacci proof](https://github.com/succinctlabs/sp1/tree/dev/examples/fibonacci) used in the test suite for the Sui Groth16 verifier and the [JWT Email Domain proof](examples/sp1-jwt-verify-email-domain) from the example directory.
  
We also provide three examples of how to use the SP1 Groth16 verifier:

- The [`examples/move/groth16-verifier`](examples/move/groth16-verifier) directory contains a sample Sui Move smart contract for verifying SP1 proofs.
- The [`examples/sp1-sui-sdk`](examples/sp1-sui-sdk) directory contains a sample example using the Sui Rust SDK for verifying SP1 proofs with PTB (Programmable Transaction Blocks).
- The [`examples/sp1-jwt-verify-email-domain`](examples/sp1-jwt-verify-email-domain) directory contains a fully-fledged example that verifies whether someone has access to a domain name without revealing their identity. This can be used as a complement to zkLogin. You can integrate it on Sui today. Follow the [blog post](https://soundness.xyz/blog/sp1sui) explaining the code.

## Requirements

- Rust
- Sui Client CLI
  - [Install Sui](https://docs.sui.io/guides/developer/getting-started/sui-install)

## Example usage

To be able to use SP1 Groth16 proofs on Sui, you need to:

1. Deploy the SP1 Groth16 verifier smart contract to Sui with your own logic. See the [SP1 Groth16 verifier smart contract](examples/move/groth16-verifier) for a vanilla example.
2. Generate a Groth16 proof using the SP1 zkVM. See the [SP1 zkVM](https://github.com/succinctlabs/sp1) repository.
3. Add the `sp1-sdk` and `sp1-sui` crates to your `Cargo.toml` in your Sui Rust SDK project.

```toml
[dependencies]
sp1-sui = { git = "https://github.com/SoundnessLabs/sp1-sui" }
sp1-sdk = { version = "4.1.0" }
```

4. Read the SP1 proof in your program and convert it to the `ark-bn254` format.

```rust
let sp1_proof_with_public_values = SP1ProofWithPublicValues::load("../../proofs/fibonacci_proof.bin").unwrap();
let (pvk, public_inputs, proof_points) =
    convert_sp1_gnark_to_ark(sp1_proof_with_public_values);
```

5. Call the `verify_groth16_bn254_proof` function of the SP1 Groth16 verifier smart contract with the verification key, public inputs and proof points.

```rust
// Add the proof components as inputs to the transaction
ptb.input(serialize_input(&pvk))?;           // Input 0: Verification key
ptb.input(serialize_input(&public_inputs))?;  // Input 1: Public inputs
ptb.input(serialize_input(&proof_points))?;   // Input 2: Proof points

let package = ObjectID::from_hex_literal(&PKG_ID).map_err(|e| anyhow!(e))?;
let module = Identifier::new("groth16_verifier").map_err(|e| anyhow!(e))?;

ptb.command(Command::move_call(
    package,
    module.clone(),
    Identifier::new("verify_groth16_bn254_proof").map_err(|e| anyhow!(e))?,
    vec![],
    vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
));
```

## Acknowledgements

This crate leverages the [`sp1`](https://github.com/succinctlabs/sp1) library by Succinct Labs for the gnark-to-ark converter and [`ark-bn254`](https://github.com/arkworks-rs/algebra) for working with the BN254 elliptic curve. The repository structure was inspired by the [`sp1-solana`](https://github.com/succinctlabs/sp1-solana) verifier.