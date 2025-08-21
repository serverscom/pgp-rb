# pgp-rb

A Ruby gem that provides PGP (Pretty Good Privacy) functionality through a fast Rust extension using the [rPGP](https://github.com/rpgp/rpgp) library.

## Features

- **Fast**: Built with Rust for high performance cryptographic operations
- **Simple API**: Easy-to-use Ruby interface for PGP operations
- **Key Parsing**: Parse and analyze both PGP public and private keys
- **Encryption**: Encrypt data using PGP public keys with configurable algorithms
- **Signing**: Sign messages using PGP private keys with various hash algorithms
- **Key Information**: Extract fingerprints, algorithms, creation dates, and expiration dates
- **Modern Crypto**: Supports RSA, EdDSA, ECDSA, and other modern algorithms
- **Latest Dependencies**: Uses pgp 0.16.0, base64 0.22.1, and other up-to-date Rust crates

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pgp-rb'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install pgp-rb
```

## Usage

### Parsing PGP Public Keys

```ruby
require 'pgp'

# Load a PGP public key from a file or string
key_data = File.read('path/to/public_key.asc')
public_key = PGP::PublicKey.parse(key_data)

# Get key information
puts public_key.fingerprint        # Key fingerprint in uppercase hex
puts public_key.algorithm          # Algorithm ID (1 for RSA, 22 for EdDSA, etc.)
puts public_key.version           # Key version (4, 5, 6)
puts public_key.created_at        # Creation timestamp
puts public_key.expires_at        # Expiration timestamp (nil if no expiration)

# Check key capabilities
puts public_key.signing_supported?      # Can this key be used for signing?
puts public_key.encryption_supported?   # Can this key be used for encryption?
```

### Parsing PGP Private Keys

```ruby
require 'pgp'

# Load a PGP private key from a file or string
private_key_data = File.read('path/to/private_key.asc')
private_key = PGP::PrivateKey.parse(private_key_data)

# Get key information (same methods as public keys)
puts private_key.fingerprint        # Key fingerprint in uppercase hex
puts private_key.algorithm          # Algorithm ID (1 for RSA, 22 for EdDSA, etc.)
puts private_key.version            # Key version (4, 5, 6)
puts private_key.created_at         # Creation timestamp
puts private_key.expires_at         # Expiration timestamp (nil if no expiration)

# Check key capabilities
puts private_key.signing_supported?      # Can this key be used for signing?
puts private_key.encryption_supported?   # Can this key be used for encryption?
```

### Signing Messages

```ruby
require 'pgp'

# Parse a private key
private_key_data = File.read('path/to/private_key.asc')
private_key = PGP::PrivateKey.parse(private_key_data)

# Sign a message with default hash algorithm (SHA-256)
signature = private_key.sign("Hello, World!")

# Sign with a specific hash algorithm
# Hash algorithm constants:
# PGP::HASH_ALGORITHM_MD5 = 1
# PGP::HASH_ALGORITHM_SHA1 = 2
# PGP::HASH_ALGORITHM_SHA256 = 8
# PGP::HASH_ALGORITHM_SHA384 = 9
# PGP::HASH_ALGORITHM_SHA512 = 10
signature = private_key.sign_with_algorithm("Secret message", PGP::HASH_ALGORITHM_SHA512)

# The result is base64-encoded signature data
puts signature
```

### Encrypting Data

```ruby
require 'pgp'

# Parse a public key
key_data = File.read('recipient_public_key.asc')
public_key = PGP::PublicKey.parse(key_data)

# Encrypt a message with default algorithm (AES-128)
encrypted_data = public_key.encrypt("Hello, World!")

# Encrypt with a specific symmetric algorithm
# Algorithm constants:
# PGP::KEY_ALGORITHM_AES_128 = 7
# PGP::KEY_ALGORITHM_AES_192 = 8
# PGP::KEY_ALGORITHM_AES_256 = 9
encrypted_data = public_key.encrypt_with_algorithm("Secret message", PGP::KEY_ALGORITHM_AES_256)

# The result is base64-encoded encrypted data
puts encrypted_data
```

### Algorithm Constants

The gem provides constants for symmetric encryption algorithms:

```ruby
PGP::KEY_ALGORITHM_IDEA = 1
PGP::KEY_ALGORITHM_TRIPLE_DES = 2
PGP::KEY_ALGORITHM_CAST5 = 3
PGP::KEY_ALGORITHM_BLOWFISH = 4
PGP::KEY_ALGORITHM_AES_128 = 7
PGP::KEY_ALGORITHM_AES_192 = 8
PGP::KEY_ALGORITHM_AES_256 = 9
PGP::KEY_ALGORITHM_TWOFISH = 10
PGP::KEY_ALGORITHM_CAMELLIA_128 = 11
PGP::KEY_ALGORITHM_CAMELLIA_192 = 12
PGP::KEY_ALGORITHM_CAMELLIA_256 = 13
```

And constants for hash algorithms used in signing:

```ruby
PGP::HASH_ALGORITHM_MD5 = 1
PGP::HASH_ALGORITHM_SHA1 = 2
PGP::HASH_ALGORITHM_SHA256 = 8
PGP::HASH_ALGORITHM_SHA384 = 9
PGP::HASH_ALGORITHM_SHA512 = 10
PGP::HASH_ALGORITHM_SHA224 = 11
PGP::HASH_ALGORITHM_SHA3_256 = 12
PGP::HASH_ALGORITHM_SHA3_512 = 14
```

### Error Handling

The gem defines specific error classes:

```ruby
begin
  public_key = PGP::PublicKey.parse(invalid_key_data)
rescue PGP::ParseError => e
  puts "Failed to parse key: #{e.message}"
end

begin
  encrypted = signing_only_key.encrypt("data")
rescue PGP::EncryptionError => e
  puts "Encryption failed: #{e.message}"
end

begin
  signature = private_key.sign("data")
rescue PGP::SigningError => e
  puts "Signing failed: #{e.message}"
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests.

### Building the Extension

This gem uses a Rust extension for performance. To build:

```bash
bundle exec rake compile
```

### Running Tests

```bash
bundle exec rspec
```

### Generating Test Keys

The repository includes a script to generate test keys for development:

```bash
ruby generate_test_keys.rb
```

This script will generate RSA and ECC key pairs (both public and private) and place them in the `spec/fixtures/` directory.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/serverscom/pgp-rb.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
