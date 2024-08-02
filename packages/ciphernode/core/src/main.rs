//! # Enclave core
//!
//! Here we have the core functionality of an enclave node.
//!
//! - Enryption
//! - Decryption
//! - Key aggregation
//! - Key storage
//!
//! We want to externalize infrastructure and deal with core computation here. Functions here make
//! use of `impl Traits` and `Fn` lambdas to specify things that we need in order to manage our core
//! functionality. They should be really easy to test.
//!
//! This code should read in a reasonably straight forward way but by writing it we will learn good
//! shapes for our infastructure dependencies.
//!
//! This puts us in good stead for both changing our infrastructure as well as allowing us to be
//! aware of what our nodes are doing.

use std::future::Future;
use fhe::bfv::SecretKey;
use rand::{CryptoRng, RngCore};

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;


// NOTE THIS IS MOCK TO TALK CONCEPTUALLY ABOUT WHAT SHOULD BE HERE
// Hypothetical core function depends on a save function that uses dependency injection
// Now after writing this we know we need an async process that takes a Secret key and persists it some how.
// Perhaps it makes sense that a std::collections::Map trait is passed in so we can store the data
// by passing in a slate instance. 
pub async fn generate_and_save_key<
    R: RngCore + CryptoRng,
    F: FnOnce(SecretKey) -> Fut,
    Fut: Future<Output = Result<()>>,
>(
    params: &std::sync::Arc<fhe::bfv::BfvParameters>, // pass in the params we use
    save: F, // pass in the thing that saves an deserializes the key
    rng: &mut R, // pass in an rng so we can test this function
) -> Result<()> {
    let sk_share: SecretKey = SecretKey::random(params, rng);
    save(sk_share).await?;
    Ok(())
}

fn main() {
    println!("Hello, cipher world!");
}

#[cfg(test)]
mod tests {
    pub type Error = Box<dyn std::error::Error>;
    pub type Result<T> = std::result::Result<T, Error>;

    use crate::*;
    use fhe::bfv::SecretKey;
    use fhe::bfv::{self, BfvParameters};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_generate_key() -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let params = gen_params();
        let expected_sk_share = SecretKey::random(&params, &mut ChaCha8Rng::seed_from_u64(42));

        let mut results: Vec<SecretKey> = vec![];

        generate_and_save_key(
            &params,
            |sk: SecretKey| async {
                results.push(sk);
                Ok(())
            },
            &mut rng,
        )
        .await?;

        let first = results[0].clone();

        assert!(results.len() == 1);
        assert!(first.eq(&expected_sk_share));

        Ok(())
    }


    
    fn gen_params() -> Arc<BfvParameters> {
        let moduli: Vec<u64> = vec![0x3FFFFFFF000001];
        let num_votes: usize = 1000;
        let degree: usize = 2048;
        let plaintext_modulus: u64 = match num_votes {
            1..=999 => 1009,
            1000..=9999 => 10007,
            10000..=99999 => 100003,
            100000..=199999 => 200003,
            200000..=299999 => 300007,
            300000..=399999 => 400009,
            400000..=499999 => 500009,
            500000..=599999 => 600011,
            600000..=699999 => 700001,
            700000..=799999 => 800011,
            800000..=899999 => 900001,
            _ => 1032193,
        };
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap()
    }

}
