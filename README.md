# hohibe — Hierarchical Identity Based Encryption

This crate provides an implementation of hierarchical identity based encryption
for Rust. For more information, please see the crate documentation (run `cargo
doc` to generate it).


## ⚠️ Warning: Cryptographic Hazmat ☣️

This crate is made for playing around with HIBE and for prototyping of applications and
protocols using HIBE. It has *not* been audited, it is *not* battle tested, and *nobody* claims
it to be secure.

Use it at **your own risk** and if you know what you are doing!

## Example Code

```rust
use hohibe::kem::HybridKem;

const MAX_DEPTH: usize = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let kem = HybridKem::new(MAX_DEPTH);
    let (public_key, master_secret) = kem.setup(&mut rng)?;

    // Encrypt for hibe.example.com
    let ciphertext = kem.encrypt(&mut rng, &public_key, &["com", "example", "hibe"], b"GET /")?;

    // Assume that the owner of example.com is given the secret key for their domain ...
    let example_com = kem.generate_key(
        &mut rng,
        &public_key,
        &master_secret,
        &["com", "example"],
    )?;
    // ... and they can use that to derive the key for the subdomain
    let secret_key = kem.derive_key(
        &mut rng,
        &public_key,
        &example_com,
        &["com", "example", "hibe"],
    )?;

    // Now we can decrypt
    let plaintext = kem.decrypt(&public_key, &secret_key, &ciphertext)?;

    assert_eq!(plaintext, b"GET /");

    Ok(())
}
```

## License

hohibe is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

hohibe is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.
