# frozen_string_literal: true

require 'spec_helper'
require 'base64'

RSpec.describe PGP::PrivateKey do
  describe '.parse' do
    context 'with invalid key' do
      let(:key) { 'invalid key' }

      specify do
        expect do
          described_class.parse(key)
        end.to raise_error(PGP::ParseError)
      end
    end

    context 'with ECC private key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect do
          described_class.parse(key)
        end.not_to raise_error
      end
    end
  end

  describe '#algorithm' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).algorithm).to eq(22)
      end
    end
  end

  describe '#algorithm_name' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).algorithm_name).to eq('EdDSA legacy format [deprecated in RFC 9580, superseded by Ed25519 (27)]')
      end
    end
  end

  describe '#version' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).version).to eq(4)
      end
    end
  end

  describe '#fingerprint' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).fingerprint).to eq('76A51CBAC7C04A095BF9A31EBB018A3C33DB1D7E')
      end
    end
  end

  describe '#created_at' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).created_at.utc.strftime('%Y-%m-%d %H:%M:%S %Z')).to eq('2025-08-21 13:04:40 UTC')
      end
    end
  end

  describe '#expires_at' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).expires_at).to be_nil
      end
    end
  end

  describe '#expired?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).expired?).to eq(false)
      end
    end
  end

  describe '#signing_supported?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).signing_supported?).to eq(true)
      end
    end
  end

  describe '#encryption_supported?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect(described_class.parse(key).encryption_supported?).to eq(false)
      end
    end
  end

  describe '#sign' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify do
        expect do
          described_class.parse(key).sign('Hello, World!')
        end.not_to raise_error
      end

      specify 'returns base64 encoded signature' do
        signature = described_class.parse(key).sign('Hello, World!')
        expect(signature).to be_a(String)
        expect(signature.length).to be > 100
        expect { Base64.decode64(signature) }.not_to raise_error
      end
    end
  end

  describe '#sign_with_algorithm' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_private_key') }

      specify 'signs with SHA256' do
        expect do
          described_class.parse(key).sign_with_algorithm('Hello, World!', PGP::HASH_ALGORITHM_SHA256)
        end.not_to raise_error
      end

      specify 'signs with SHA512' do
        expect do
          described_class.parse(key).sign_with_algorithm('Hello, World!', PGP::HASH_ALGORITHM_SHA512)
        end.not_to raise_error
      end

      specify 'raises error with unsupported algorithm' do
        expect do
          described_class.parse(key).sign_with_algorithm('Hello, World!', 999)
        end.to raise_error(PGP::SigningError, 'Unsupported hash algorithm')
      end
    end
  end
end
