use crate::key::{self, PublicKey};
use alloc::vec::Vec;
use crate::errors::{Error, Result};
#[inline]
pub fn encrypt<PK: PublicKey>(pub_key: &PK, msg: &[u8]) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let k = pub_key.size();
    if msg.len() > k {
        return Err(Error::MessageTooLong);
    }
    let mut em = vec![0u8; k];
    em.copy_from_slice(msg);
    pub_key.raw_encryption_primitive(&em, pub_key.size())
}
