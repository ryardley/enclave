use async_trait::async_trait;
use fhe::bfv::SecretKey;
use mockall::automock;
use rand::{CryptoRng, RngCore};

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

fn main() {
    println!("Hello, cipher world!");
}

#[async_trait]
#[automock]
pub trait AsyncMap<T> {
    async fn set(&self, key: &str, asset: T) -> Result<()>;
    async fn get(&self, key: &str) -> T;
}

pub async fn generate_key<R: RngCore + CryptoRng>(
    params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    keystore: &impl AsyncMap<SecretKey>,
    rng: &mut R,
) -> Result<()> {
    let sk_share: SecretKey = SecretKey::random(params, rng);
    keystore.set("secret_key", sk_share).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    pub type Error = Box<dyn std::error::Error>;
    pub type Result<T> = std::result::Result<T, Error>;

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use crate::{generate_key, MockAsyncMap};
    use fhe::bfv::SecretKey;
    use fhe::bfv::{self, BfvParameters};
    use mockall::predicate::{eq, function};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

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
    
    fn async_ok_with<T>(value: T) -> Pin<Box<dyn Future<Output = Result<T>> + Send>>
    where
        T: Send + 'static,
    {
        Box::pin(async move { Ok(value) })
    }

    #[tokio::test]
    async fn test_generate_key() -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let ks = &mut MockAsyncMap::new();
        let params = gen_params();
        let expected_sk_share = SecretKey::random(&params, &mut ChaCha8Rng::seed_from_u64(42));

        ks.expect_set()
            .with(
                eq("secret_key"),
                function(move |sk: &SecretKey| {
                    let expected = expected_sk_share.clone();
                    let is_eq = sk.eq(&expected);
                    println!("iseq::{:?}", is_eq);
                    return is_eq;
                }),
            )
            .returning(|_, _| async_ok_with(()));

        generate_key(&params, ks, &mut rng).await?;

        Ok(())
    }
}
