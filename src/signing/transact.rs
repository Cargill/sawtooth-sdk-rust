/*
 * Copyright 2020 Cargill Incorporated
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use transact::signing::Error as TransactSigningError;

use super::{hex_str_to_bytes, Context, Error, PrivateKey, PublicKey, Signer};

pub struct TransactSigner {
    inner_signer: Signer<'static>,
    public_key: Box<dyn PublicKey>,
}

impl TransactSigner {
    pub fn new(context: Box<dyn Context>, private_key: Box<dyn PrivateKey>) -> Result<Self, Error> {
        let public_key = context.get_public_key(&*private_key)?;
        Ok(Self {
            inner_signer: Signer::new_boxed(context, private_key),
            public_key,
        })
    }
}

impl transact::signing::Signer for TransactSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TransactSigningError> {
        Ok(self
            .inner_signer
            .sign(message)
            .and_then(|hex| hex_str_to_bytes(&hex))?)
    }

    fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }
}

impl From<Error> for TransactSigningError {
    fn from(err: Error) -> TransactSigningError {
        TransactSigningError::SigningError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{bytes_to_hex_str, create_context, secp256k1::Secp256k1PrivateKey};
    use super::*;

    use transact::signing::Signer as _;

    static KEY_PRIV_HEX: &'static str =
        "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
    static KEY_PUB_HEX: &'static str =
        "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";
    static MSG: &'static str = "test";
    static MSG_KEY_SIG: &'static str = "5195115d9be2547b720ee74c23dd841842875db6eae1f5da8605b050a49e702b4aa83be72ab7e3cb20f17c657011b49f4c8632be2745ba4de79e6aa05da57b35";

    #[test]
    fn transact_secp256k1_signer() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let priv_key = Secp256k1PrivateKey::from_hex(KEY_PRIV_HEX).unwrap();
        assert_eq!(priv_key.get_algorithm_name(), "secp256k1");
        assert_eq!(priv_key.as_hex(), KEY_PRIV_HEX);

        let signer = TransactSigner::new(context, Box::new(priv_key))
            .expect("failed to create transact signer");

        let signature = signer
            .sign(&String::from(MSG).into_bytes())
            .expect("failed to sign msg");
        assert_eq!(&bytes_to_hex_str(&signature), MSG_KEY_SIG);
        assert_eq!(&bytes_to_hex_str(signer.public_key()), KEY_PUB_HEX)
    }
}
