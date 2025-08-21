use magnus::{
    function, method,
    prelude::*,
    exception::ExceptionClass,
    value::Lazy,
    Error, Ruby, RModule, Time, Integer
};

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::crypto::hash::HashAlgorithm;
use pgp::composed::MessageBuilder;
use pgp::types::KeyDetails;
use pgp::types::{KeyVersion, PublicKeyTrait, Password};

use std::io::Cursor;
use base64::{engine::general_purpose, Engine as _};

static PGP: Lazy<RModule> = Lazy::new(|ruby| ruby.define_module("PGP").unwrap());

static PGP_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    ruby
        .get_inner(&PGP)
        .define_error("Error", ruby.exception_standard_error())
        .unwrap()
});

static PGP_PARSE_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    ruby
        .get_inner(&PGP)
        .define_error("ParseError", ruby.get_inner(&PGP_ERROR))
        .unwrap()
});

static PGP_ENCRYPTION_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    ruby
        .get_inner(&PGP)
        .define_error("EncryptionError", ruby.get_inner(&PGP_ERROR))
        .unwrap()
});

static PGP_SIGNING_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    ruby
        .get_inner(&PGP)
        .define_error("SigningError", ruby.get_inner(&PGP_ERROR))
        .unwrap()
});

fn parse(ruby: &Ruby, input: String) -> Result<PgpPublicKey, Error> {
     let cursor = Cursor::new(input.clone());

    match SignedPublicKey::from_armor_single(cursor) {
        Ok((public_key, _)) => {
            Ok(PgpPublicKey{
                signed_public_key: public_key
            })
        },
        Err(e) => {
            let error_message = format!("can't parse input: {}", e);
            Err(Error::new(ruby.get_inner(&PGP_PARSE_ERROR), error_message))
        }
    }
}

fn parse_private_key(ruby: &Ruby, input: String) -> Result<PgpPrivateKey, Error> {
    let cursor = Cursor::new(input.clone());

    match SignedSecretKey::from_armor_single(cursor) {
        Ok((secret_key, _)) => {
            Ok(PgpPrivateKey{
                signed_secret_key: secret_key
            })
        },
        Err(e) => {
            let error_message = format!("can't parse private key: {}", e);
            Err(Error::new(ruby.get_inner(&PGP_PARSE_ERROR), error_message))
        }
    }
}

#[magnus::wrap(class = "PGP::PublicKey", free_immediately, size)]
struct PgpPublicKey {
    signed_public_key: SignedPublicKey
}

impl PgpPublicKey {
    fn fingerprint(rb_self: &PgpPublicKey) -> String {
       rb_self.signed_public_key
        .fingerprint()
        .as_bytes().iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
        .to_uppercase()
    }

    fn algorithm(rb_self: &PgpPublicKey) -> Option<u8> {
        match rb_self.signed_public_key.algorithm() {
            PublicKeyAlgorithm::RSA => Some(1),
            PublicKeyAlgorithm::RSAEncrypt => Some(2),
            PublicKeyAlgorithm::RSASign => Some(3),
            PublicKeyAlgorithm::DSA => Some(17),
            PublicKeyAlgorithm::ECDH => Some(18),
            PublicKeyAlgorithm::ECDSA => Some(19),
            PublicKeyAlgorithm::Elgamal => Some(20),
            PublicKeyAlgorithm::DiffieHellman => Some(21),
            PublicKeyAlgorithm::EdDSALegacy => Some(22),
            PublicKeyAlgorithm::X25519 => Some(25),
            PublicKeyAlgorithm::X448 => Some(26),
            PublicKeyAlgorithm::Ed25519 => Some(27),
            PublicKeyAlgorithm::Ed448 => Some(28),
            PublicKeyAlgorithm::Private100 => Some(100),
            PublicKeyAlgorithm::Private101 => Some(101),
            PublicKeyAlgorithm::Private102 => Some(102),
            PublicKeyAlgorithm::Private103 => Some(103),
            PublicKeyAlgorithm::Private104 => Some(104),
            PublicKeyAlgorithm::Private105 => Some(105),
            PublicKeyAlgorithm::Private106 => Some(106),
            PublicKeyAlgorithm::Private107 => Some(107),
            PublicKeyAlgorithm::Private108 => Some(108),
            PublicKeyAlgorithm::Private109 => Some(109),
            PublicKeyAlgorithm::Private110 => Some(110),
            PublicKeyAlgorithm::Unknown(_) => None,
            _ => None,
        }
    }

    fn is_signing_key(rb_self: &PgpPublicKey) -> bool {
        rb_self.signed_public_key.is_signing_key()
    }

    fn is_encryption_key(rb_self: &PgpPublicKey) -> bool {
        rb_self.signed_public_key.is_encryption_key()
    }

    fn version(rb_self: &PgpPublicKey) -> Option<u8> {
        match rb_self.signed_public_key.primary_key.version() {
            KeyVersion::V2 => Some(2),
            KeyVersion::V3 => Some(3),
            KeyVersion::V4 => Some(4),
            KeyVersion::V5 => Some(5),
            KeyVersion::V6 => Some(6),
            KeyVersion::Other(_) => None
        }
    }

    fn created_at(ruby: &Ruby, rb_self: &PgpPublicKey) -> Result<Time, Error> {
        let time = rb_self.signed_public_key.primary_key.created_at();

        ruby.time_new(
            time.timestamp(),
            0
        )
    }

    fn expires_at(ruby: &Ruby, rb_self: &PgpPublicKey) -> Result<Option<Time>,Error> {
        match rb_self.signed_public_key.expires_at() {
            Some(dt) => match ruby.time_new(dt.timestamp(), 0) {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(e)
            },
            None => Ok(None)
        }
    }

    fn encrypt_with_algorithm(ruby: &Ruby, rb_self: &PgpPublicKey, input: String, algorithm: Integer) -> Result<String, Error> {
        let alg = match algorithm.to_u8() {
            Ok(v) => SymmetricKeyAlgorithm::from(v),
            Err(e) => return Err(e)
        };

        let input_bytes = input.into_bytes();
        let mut builder = MessageBuilder::from_bytes("", input_bytes)
            .seipd_v1(&mut rand::thread_rng(), alg);

        builder.encrypt_to_key(&mut rand::thread_rng(), &rb_self.signed_public_key)
            .map_err(|e| Error::new(ruby.get_inner(&PGP_ENCRYPTION_ERROR), format!("Failed to add encryption key: {}", e)))?;

        let result = builder.to_vec(&mut rand::thread_rng())
            .map_err(|e| Error::new(ruby.get_inner(&PGP_ENCRYPTION_ERROR), format!("Failed to encrypt: {}", e)))?;

        Ok(general_purpose::STANDARD.encode(result))
    }
}

#[magnus::wrap(class = "PGP::PrivateKey", free_immediately, size)]
struct PgpPrivateKey {
    signed_secret_key: SignedSecretKey
}

impl PgpPrivateKey {
    fn fingerprint(rb_self: &PgpPrivateKey) -> String {
        rb_self.signed_secret_key
            .fingerprint()
            .as_bytes().iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
            .to_uppercase()
    }

    fn algorithm(rb_self: &PgpPrivateKey) -> Option<u8> {
        match rb_self.signed_secret_key.algorithm() {
            PublicKeyAlgorithm::RSA => Some(1),
            PublicKeyAlgorithm::RSAEncrypt => Some(2),
            PublicKeyAlgorithm::RSASign => Some(3),
            PublicKeyAlgorithm::DSA => Some(17),
            PublicKeyAlgorithm::ECDH => Some(18),
            PublicKeyAlgorithm::ECDSA => Some(19),
            PublicKeyAlgorithm::Elgamal => Some(20),
            PublicKeyAlgorithm::DiffieHellman => Some(21),
            PublicKeyAlgorithm::EdDSALegacy => Some(22),
            PublicKeyAlgorithm::X25519 => Some(25),
            PublicKeyAlgorithm::X448 => Some(26),
            PublicKeyAlgorithm::Ed25519 => Some(27),
            PublicKeyAlgorithm::Ed448 => Some(28),
            PublicKeyAlgorithm::Private100 => Some(100),
            PublicKeyAlgorithm::Private101 => Some(101),
            PublicKeyAlgorithm::Private102 => Some(102),
            PublicKeyAlgorithm::Private103 => Some(103),
            PublicKeyAlgorithm::Private104 => Some(104),
            PublicKeyAlgorithm::Private105 => Some(105),
            PublicKeyAlgorithm::Private106 => Some(106),
            PublicKeyAlgorithm::Private107 => Some(107),
            PublicKeyAlgorithm::Private108 => Some(108),
            PublicKeyAlgorithm::Private109 => Some(109),
            PublicKeyAlgorithm::Private110 => Some(110),
            PublicKeyAlgorithm::Unknown(_) => None,
            _ => None,
        }
    }

    fn is_signing_key(rb_self: &PgpPrivateKey) -> bool {
        rb_self.signed_secret_key.signed_public_key().is_signing_key()
    }

    fn is_encryption_key(rb_self: &PgpPrivateKey) -> bool {
        rb_self.signed_secret_key.signed_public_key().is_encryption_key()
    }

    fn version(rb_self: &PgpPrivateKey) -> Option<u8> {
        match rb_self.signed_secret_key.primary_key.version() {
            KeyVersion::V2 => Some(2),
            KeyVersion::V3 => Some(3),
            KeyVersion::V4 => Some(4),
            KeyVersion::V5 => Some(5),
            KeyVersion::V6 => Some(6),
            KeyVersion::Other(_) => None
        }
    }

    fn created_at(ruby: &Ruby, rb_self: &PgpPrivateKey) -> Result<Time, Error> {
        let public_key = rb_self.signed_secret_key.signed_public_key();
        let time = public_key.created_at();

        ruby.time_new(
            time.timestamp(),
            0
        )
    }

    fn expires_at(ruby: &Ruby, rb_self: &PgpPrivateKey) -> Result<Option<Time>, Error> {
        match rb_self.signed_secret_key.expires_at() {
            Some(dt) => match ruby.time_new(dt.timestamp(), 0) {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(e)
            },
            None => Ok(None)
        }
    }

    fn sign_with_algorithm(ruby: &Ruby, rb_self: &PgpPrivateKey, input: String, hash_algorithm: Integer) -> Result<String, Error> {
        let hash_alg = match hash_algorithm.to_u8() {
            Ok(1) => HashAlgorithm::Md5,
            Ok(2) => HashAlgorithm::Sha1,
            Ok(8) => HashAlgorithm::Sha256,
            Ok(9) => HashAlgorithm::Sha384,
            Ok(10) => HashAlgorithm::Sha512,
            Ok(11) => HashAlgorithm::Sha224,
            Ok(12) => HashAlgorithm::Sha3_256,
            Ok(14) => HashAlgorithm::Sha3_512,
            Ok(_) => return Err(Error::new(ruby.get_inner(&PGP_SIGNING_ERROR), "Unsupported hash algorithm")),
            Err(_) => return Err(Error::new(ruby.get_inner(&PGP_SIGNING_ERROR), "Unsupported hash algorithm"))
        };

        let input_bytes = input.into_bytes();
        let mut builder = MessageBuilder::from_bytes("", input_bytes);

        builder.sign(&rb_self.signed_secret_key.primary_key, Password::from(""), hash_alg);

        let result = builder.to_vec(&mut rand::thread_rng())
            .map_err(|e| Error::new(ruby.get_inner(&PGP_SIGNING_ERROR), format!("Failed to sign: {}", e)))?;

        Ok(general_purpose::STANDARD.encode(result))
    }

    fn sign(ruby: &Ruby, rb_self: &PgpPrivateKey, input: String) -> Result<String, Error> {
        Self::sign_with_algorithm(ruby, rb_self, input, Integer::from_i64(8))
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let _ = Lazy::force(&PGP, ruby);
    let _ = Lazy::force(&PGP_ERROR, ruby);
    let _ = Lazy::force(&PGP_PARSE_ERROR, ruby);
    let _ = Lazy::force(&PGP_ENCRYPTION_ERROR, ruby);
    let _ = Lazy::force(&PGP_SIGNING_ERROR, ruby);

    let module = ruby.get_inner(&PGP);

    let public_key = module.define_class("PublicKey", ruby.class_object())?;
    let _ = public_key.define_singleton_method("parse", function!(parse, 1));
    let _ = public_key.define_method("fingerprint", method!(PgpPublicKey::fingerprint, 0));
    let _ = public_key.define_method("algorithm", method!(PgpPublicKey::algorithm, 0));
    let _ = public_key.define_method("version", method!(PgpPublicKey::version, 0));
    let _ = public_key.define_method("created_at", method!(PgpPublicKey::created_at, 0));
    let _ = public_key.define_method("expires_at", method!(PgpPublicKey::expires_at, 0));
    let _ = public_key.define_method("signing_supported?", method!(PgpPublicKey::is_signing_key, 0));
    let _ = public_key.define_method("encryption_supported?", method!(PgpPublicKey::is_encryption_key, 0));
    let _ = public_key.define_method("encrypt_with_algorithm", method!(PgpPublicKey::encrypt_with_algorithm, 2));

    let private_key = module.define_class("PrivateKey", ruby.class_object())?;
    let _ = private_key.define_singleton_method("parse", function!(parse_private_key, 1));
    let _ = private_key.define_method("fingerprint", method!(PgpPrivateKey::fingerprint, 0));
    let _ = private_key.define_method("algorithm", method!(PgpPrivateKey::algorithm, 0));
    let _ = private_key.define_method("version", method!(PgpPrivateKey::version, 0));
    let _ = private_key.define_method("created_at", method!(PgpPrivateKey::created_at, 0));
    let _ = private_key.define_method("expires_at", method!(PgpPrivateKey::expires_at, 0));
    let _ = private_key.define_method("signing_supported?", method!(PgpPrivateKey::is_signing_key, 0));
    let _ = private_key.define_method("encryption_supported?", method!(PgpPrivateKey::is_encryption_key, 0));
    let _ = private_key.define_method("sign", method!(PgpPrivateKey::sign, 1));
    let _ = private_key.define_method("sign_with_algorithm", method!(PgpPrivateKey::sign_with_algorithm, 2));

    Ok(())
}
