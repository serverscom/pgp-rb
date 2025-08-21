# frozen_string_literal: true

begin
  /(?<ruby_version>\d+\.\d+)/ =~ RUBY_VERSION
  require_relative "pgp-rb/#{ruby_version}/pgp_rb"
rescue LoadError
  require_relative 'pgp-rb/pgp_rb'
end

module PGP
  KEY_ALGORITHM_RSA = 1
  KEY_ALGORITHM_RSA_ENCRYPT = 2
  KEY_ALGORITHM_RSA_SIGN = 3
  KEY_ALGORITHM_ELGAMAL_SIGN = 16
  KEY_ALGORITHM_DSA = 17
  KEY_ALGORITHM_ECDH = 18
  KEY_ALGORITHM_ECDSA = 19
  KEY_ALGORITHM_ELGAMAL = 20
  KEY_ALGORITHM_DIFFIE_HELLMAN = 21
  KEY_ALGORITHM_EDDSA_LEGACY = 22
  KEY_ALGORITHM_X25519 = 25
  KEY_ALGORITHM_X448 = 26
  KEY_ALGORITHM_ED25519 = 27
  KEY_ALGORITHM_ED448 = 28

  KEY_ALGORITHM_NAMES = {
    KEY_ALGORITHM_RSA => 'RSA (Encrypt and Sign)',
    KEY_ALGORITHM_RSA_ENCRYPT => 'RSA (Encrypt-Only)',
    KEY_ALGORITHM_RSA_SIGN => 'RSA (Sign-Only)',
    KEY_ALGORITHM_ELGAMAL_SIGN => 'Elgamal (Sign-Only)',
    KEY_ALGORITHM_DSA => 'DSA (Digital Signature Algorithm)',
    KEY_ALGORITHM_ECDH => 'Elliptic Curve: RFC-6637',
    KEY_ALGORITHM_ECDSA => 'ECDSA: RFC-6637',
    KEY_ALGORITHM_ELGAMAL => 'Elgamal (Encrypt and Sign)',
    KEY_ALGORITHM_DIFFIE_HELLMAN => 'Diffie-Hellman (X9.42, as defined for IETF-S/MIME)',
    KEY_ALGORITHM_EDDSA_LEGACY => 'EdDSA legacy format [deprecated in RFC 9580, superseded by Ed25519 (27)]',
    KEY_ALGORITHM_X25519 => 'X25519 [RFC 9580]',
    KEY_ALGORITHM_X448 => 'X448 [RFC 9580]',
    KEY_ALGORITHM_ED25519 => 'Ed25519 [RFC 9580]',
    KEY_ALGORITHM_ED448 => 'Ed448 [RFC 9580]'
  }.freeze

  ENCRIPTION_ALGORITHM_IDEA = 1
  ENCRIPTION_ALGORITHM_TRIPLE_DES = 2
  ENCRIPTION_ALGORITHM_CAST5 = 3
  ENCRIPTION_ALGORITHM_BLOWFISH = 4
  ENCRIPTION_ALGORITHM_AES_128 = 7
  ENCRIPTION_ALGORITHM_AES_192 = 8
  ENCRIPTION_ALGORITHM_AES_256 = 9
  ENCRIPTION_ALGORITHM_TWOFISH = 10
  ENCRIPTION_ALGORITHM_CAMELLIA_128 = 11
  ENCRIPTION_ALGORITHM_CAMELLIA_192 = 12
  ENCRIPTION_ALGORITHM_CAMELLIA_256 = 13

  HASH_ALGORITHM_MD5 = 1
  HASH_ALGORITHM_SHA1 = 2
  HASH_ALGORITHM_SHA256 = 8
  HASH_ALGORITHM_SHA384 = 9
  HASH_ALGORITHM_SHA512 = 10
  HASH_ALGORITHM_SHA224 = 11
  HASH_ALGORITHM_SHA3_256 = 12
  HASH_ALGORITHM_SHA3_512 = 14

  HASH_ALGORITHM_NAMES = {
    HASH_ALGORITHM_MD5 => 'MD5',
    HASH_ALGORITHM_SHA1 => 'SHA1',
    HASH_ALGORITHM_SHA256 => 'SHA256',
    HASH_ALGORITHM_SHA384 => 'SHA384',
    HASH_ALGORITHM_SHA512 => 'SHA512',
    HASH_ALGORITHM_SHA224 => 'SHA224',
    HASH_ALGORITHM_SHA3_256 => 'SHA3-256',
    HASH_ALGORITHM_SHA3_512 => 'SHA3-512'
  }.freeze

  # Public Key class provides an native extension representation for working with PGP public keys.
  class PublicKey
    private_class_method :new

    # @!method self.parse
    #   Parses a PGP public key from a given string input.
    #   @param input [String] the PGP public key in string format.
    #   @return [PublicKey] an instance of PublicKey if parsing is successful.

    # @!method fingerprint
    #   Returns the fingerprint of the public key.
    #   @return [String] the fingerprint of the public key.

    # @!method algorithm
    #   Returns the algorithm used by the public key.
    #   @return [Integer] the algorithm identifier.

    # @!method signing_supported?
    #   Checks if the public key supports signing.
    #   @return [Boolean] true if the key supports signing, false otherwise.

    # @!method ENCRIPTION_supported?
    #   Checks if the public key supports ENCRIPTION.
    #   @return [Boolean] true if the key supports ENCRIPTION, false otherwise.

    # @!method version
    #   Returns the version of the public key.
    #   @return [Integer] the version of the public key.

    # @!method created_at
    #   Returns the creation time of the public key.
    #   @return [Time] the creation time of the public key.

    # @!method expires_at
    #   Returns the expiration time of the public key, if any.
    #   @return [Time, nil] the expiration time of the public key or nil if it does not expire.

    # @!method encrypt_with_algorithm(input, algorithm)
    #   Encrypts data with the specified algorithm.
    #   @param input [String] the data to be encrypted.
    #   @param algorithm [Integer] the ENCRIPTION algorithm identifier.
    #   @return [String] the encrypted data encoded by base64.

    # Returns a string representation of the PublicKey object, including its fingerprint, algorithm name, and version.
    # @return [String] the string representation of the PublicKey object.
    def inspect
      "#<#{self.class} #{fingerprint} #{algorithm_name} v#{version}>"
    end

    # Fetches the name of the algorithm used by the public key from a predefined list of names.
    # @return [String] the name of the algorithm.
    def algorithm_name
      KEY_ALGORITHM_NAMES.fetch(algorithm, 'Unknown')
    end

    # Checks whether the public key has expired.
    # @return [Boolean] true if the key has expired, false otherwise.
    def expired?
      return false if expires_at.nil?

      expires_at.to_i <= Time.now.to_i
    end

    # Encrypts data using the specified ENCRIPTION algorithm.
    # @param data [String] the data to be encrypted.
    # @param algorithm [Integer] the ENCRIPTION algorithm to use, defaults to AES-128.
    # @return [String] the encrypted data encoded by base64.
    def encrypt(data, algorithm = ENCRIPTION_ALGORITHM_AES_128)
      encrypt_with_algorithm(data, algorithm)
    end
  end

  # Private Key class provides an native extension representation for working with PGP private keys.
  class PrivateKey
    private_class_method :new

    # @!method self.parse
    #   Parses a PGP private key from a given string input.
    #   @param input [String] the PGP private key in string format.
    #   @return [PrivateKey] an instance of PrivateKey if parsing is successful.

    # @!method fingerprint
    #   Returns the fingerprint of the private key.
    #   @return [String] the fingerprint of the private key.

    # @!method algorithm
    #   Returns the algorithm used by the private key.
    #   @return [Integer] the algorithm identifier.

    # @!method signing_supported?
    #   Checks if the private key supports signing.
    #   @return [Boolean] true if the key supports signing, false otherwise.

    # @!method encryption_supported?
    #   Checks if the private key supports encryption.
    #   @return [Boolean] true if the key supports encryption, false otherwise.

    # @!method version
    #   Returns the version of the private key.
    #   @return [Integer] the version of the private key.

    # @!method created_at
    #   Returns the creation time of the private key.
    #   @return [Time] the creation time of the private key.

    # @!method expires_at
    #   Returns the expiration time of the private key, if any.
    #   @return [Time, nil] the expiration time of the private key or nil if it does not expire.

    # @!method sign_with_algorithm(input, algorithm)
    #   Signs data with the specified hash algorithm.
    #   @param input [String] the data to be signed.
    #   @param algorithm [Integer] the hash algorithm identifier.
    #   @return [String] the signed data encoded by base64.

    # @!method sign(input)
    #   Signs data with the default hash algorithm (SHA256).
    #   @param input [String] the data to be signed.
    #   @return [String] the signed data encoded by base64.

    # Returns a string representation of the PrivateKey object, including its fingerprint, algorithm name, and version.
    # @return [String] the string representation of the PrivateKey object.
    def inspect
      "#<#{self.class} #{fingerprint} #{algorithm_name} v#{version}>"
    end

    # Fetches the name of the algorithm used by the private key from a predefined list of names.
    # @return [String] the name of the algorithm.
    def algorithm_name
      KEY_ALGORITHM_NAMES.fetch(algorithm, 'Unknown')
    end

    # Checks whether the private key has expired.
    # @return [Boolean] true if the key has expired, false otherwise.
    def expired?
      return false if expires_at.nil?

      expires_at.to_i <= Time.now.to_i
    end
  end
end
