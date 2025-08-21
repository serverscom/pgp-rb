# frozen_string_literal: true

RSpec.describe PGP::PublicKey do
  describe '.parse' do
    context 'with invalid key' do
      specify do
        expect { described_class.parse('invalid') }.to raise_error(::PGP::ParseError)
      end
    end

    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect { described_class.parse(key) }.not_to raise_error
      end

      context 'with private key' do
        let(:key) { File.read('spec/fixtures/ecc_private_key') }

        specify do
          expect { described_class.parse(key) }.to raise_error(::PGP::ParseError)
        end
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect { described_class.parse(key) }.not_to raise_error
      end

      context 'with private key' do
        let(:key) { File.read('spec/fixtures/rsa_private_key') }

        specify do
          expect { described_class.parse(key) }.to raise_error(::PGP::ParseError)
        end
      end
    end
  end

  describe '#algorithm' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).algorithm).to eq(PGP::KEY_ALGORITHM_EDDSA_LEGACY)
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).algorithm).to eq(PGP::KEY_ALGORITHM_RSA)
      end
    end
  end

  describe '#algorithm_name' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).algorithm_name).to eq(PGP::KEY_ALGORITHM_NAMES[PGP::KEY_ALGORITHM_EDDSA_LEGACY])
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).algorithm_name).to eq(PGP::KEY_ALGORITHM_NAMES[PGP::KEY_ALGORITHM_RSA])
      end
    end
  end

  describe '#version' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).version).to eq(4)
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).version).to eq(4)
      end
    end
  end

  describe '#fingerprint' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).fingerprint).to eq('BFCC78826A7E059057FE0BD0AFEDF82707C9B0E5')
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).fingerprint).to eq('892DB77152A1DC57374EF0EF0D9B81FD16DC6C51')
      end
    end
  end

  describe '#created_at' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).created_at.utc.to_s).to eq('2024-02-26 10:33:15 UTC')
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).created_at.utc.to_s).to eq('2024-02-26 11:29:15 UTC')
      end
    end
  end

  describe '#expired_at' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).expires_at).to be_nil
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).expires_at).to be_nil
      end
    end
  end

  describe '#expired?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).expired?).to eq(false)
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).expired?).to eq(false)
      end
    end
  end

  describe '#signing_supported?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).signing_supported?).to eq(true)
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).signing_supported?).to eq(true)
      end
    end
  end

  describe '#encryption_supported?' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect(described_class.parse(key).encryption_supported?).to eq(false)
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect(described_class.parse(key).encryption_supported?).to eq(true)
      end
    end
  end

  describe '#encrypt' do
    context 'with ECC key' do
      let(:key) { File.read('spec/fixtures/ecc_public_key') }

      specify do
        expect do
          described_class.parse(key).encrypt('foo')
        end.to raise_error(PGP::EncryptionError, "Failed to add encryption key: EdDSALegacy is only used for signing")
      end
    end

    context 'with RSA key' do
      let(:key) { File.read('spec/fixtures/rsa_public_key') }

      specify do
        expect do
          described_class.parse(key).encrypt('foo')
        end.not_to raise_error
      end
    end
  end
end
