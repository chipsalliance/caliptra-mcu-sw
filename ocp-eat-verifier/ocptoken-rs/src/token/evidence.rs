// Licensed under the Apache-2.0 license


use coset::{CborSerializable, CoseSign1, Header};
use crate::error::{OcpEatError, OcpEatResult};

pub struct Evidence {
    pub signed_eat: Option<CoseSign1>,

}

impl Default for Evidence {
    fn default() -> Self {
        Evidence { signed_eat: None }
    }
}

impl Evidence {
    pub fn new(signed_eat: CoseSign1) -> Self {
        Evidence { signed_eat: Some(signed_eat) }
    }
    pub fn decode(slice: &[u8]) -> OcpEatResult<Self> {
        //1. Implement decoding logic here
        //2. After decoding, parse the certificate from x5chain field in the unprotected header
        // and extract public key
        //3. Verify the signature of the CoseSign1 object using the public key
        todo!("Implement decode logic here and set ocp_cwt in Evidence struct");
    }
}