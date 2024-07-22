use magnus::{
    function, method,
    prelude::*,
    exception::ExceptionClass,
    value::Lazy,
    Error, Ruby, RModule, Time, Integer
};

use pgp::composed::{Message, Deserializable, SignedPublicKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::composed::message::ArmorOptions;

use pgp::types::KeyVersion;
use pgp::types::KeyTrait;

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

#[magnus::wrap(class = "PGP::PublicKey", free_immediately, size)]
struct PgpPublicKey {
    signed_public_key: SignedPublicKey
}

impl PgpPublicKey {
    fn fingerprint(rb_self: &PgpPublicKey) -> String {
       rb_self.signed_public_key
        .fingerprint()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
        .to_uppercase()
    }

    fn algorithm(rb_self: &PgpPublicKey) -> Option<u8> {
        match rb_self.signed_public_key.algorithm() {
            PublicKeyAlgorithm::RSA => Some(1),
            PublicKeyAlgorithm::RSAEncrypt => Some(2),
            PublicKeyAlgorithm::RSASign => Some(3),
            PublicKeyAlgorithm::ElgamalSign => Some(16),
            PublicKeyAlgorithm::DSA => Some(17),
            PublicKeyAlgorithm::ECDH => Some(18),
            PublicKeyAlgorithm::ECDSA => Some(19),
            PublicKeyAlgorithm::Elgamal => Some(20),
            PublicKeyAlgorithm::DiffieHellman => Some(21),
            PublicKeyAlgorithm::EdDSA => Some(22),
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

        let msg = Message::new_literal("", &input.to_string());
        let encrypted = msg.encrypt_to_keys(
            &mut rand::thread_rng(),
            alg,
            &[&rb_self.signed_public_key]
        );

        match encrypted {
            Ok(v) => {
                match v.to_armored_string(ArmorOptions::default()) {
                    Ok(s) => Ok(general_purpose::STANDARD.encode(s)),
                    Err(e) => {
                        let error_message = format!("can't convert encrpyted to string: {}", e);
                        Err(Error::new(ruby.get_inner(&PGP_ENCRYPTION_ERROR), error_message))
                    }
                }
            },
            Err(e) => {
                let error_message = format!("can't encrypt message: {}", e);
                Err(Error::new(ruby.get_inner(&PGP_ENCRYPTION_ERROR), error_message))
            }
        }
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let _ = Lazy::force(&PGP, ruby);
    let _ = Lazy::force(&PGP_ERROR, ruby);
    let _ = Lazy::force(&PGP_PARSE_ERROR, ruby);
    let _ = Lazy::force(&PGP_ENCRYPTION_ERROR, ruby);

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

    Ok(())
}
