#!/usr/bin/env ruby

require 'open3'
require 'fileutils'

# Configuration
RSA_KEY_SIZE = 2048
ECC_CURVE = "ed25519"
FIXTURES_DIR = "spec/fixtures"
TEMP_DIR = "/tmp/pgp_test_keys"

# Key configurations
KEYS = [
  {
    name: "rsa",
    type: "rsa",
    size: RSA_KEY_SIZE,
    private_file: "rsa_private_key",
    public_file: "rsa_public_key"
  },
  {
    name: "ecc",
    type: "eddsa",
    curve: ECC_CURVE,
    private_file: "ecc_private_key",
    public_file: "ecc_public_key"
  }
]

def run_command(cmd)
  puts "Running: #{cmd}"
  stdout, stderr, status = Open3.capture3(cmd)

  unless status.success?
    puts "Error running command: #{cmd}"
    puts "STDERR: #{stderr}"
    exit 1
  end

  stdout
end

def check_gpg_installed
  begin
    run_command("gpg --version")
    puts "✓ GPG is installed"
  rescue
    puts "✗ GPG is not installed. Please install it first:"
    puts "  macOS: brew install gnupg"
    puts "  Ubuntu: sudo apt-get install gnupg"
    exit 1
  end
end

def setup_temp_dir
  FileUtils.rm_rf(TEMP_DIR)
  FileUtils.mkdir_p(TEMP_DIR)
  # Set proper permissions for GPG home directory
  FileUtils.chmod(0700, TEMP_DIR)
  puts "✓ Created temporary directory: #{TEMP_DIR}"
end

def setup_fixtures_dir
  FileUtils.mkdir_p(FIXTURES_DIR)
  puts "✓ Ensured fixtures directory exists: #{FIXTURES_DIR}"
end

def generate_rsa_key(name, size)
  puts "\n🔑 Generating RSA #{size}-bit key pair..."

  temp_dir = "#{TEMP_DIR}/#{name}"
  FileUtils.mkdir_p(temp_dir)
  FileUtils.chmod(0700, temp_dir)

  # Generate key with batch mode
  batch_file = "#{temp_dir}/batch.txt"
  File.write(batch_file, <<~BATCH)
    %echo Generating RSA key
    Key-Type: RSA
    Key-Length: #{size}
    Subkey-Type: RSA
    Subkey-Length: #{size}
    Name-Real: Test User RSA
    Name-Comment: Generated for pgp-rb tests
    Name-Email: test-rsa@example.com
    Expire-Date: 0
    %no-protection
    %commit
    %echo done
  BATCH

  # Generate key
  run_command("env GNUPGHOME=#{temp_dir} gpg --batch --generate-key #{batch_file}")

  # Get key ID
  output = run_command("env GNUPGHOME=#{temp_dir} gpg --list-secret-keys --with-colons")
  key_id = output.lines.find { |line| line.start_with?('sec:') }&.split(':')&.[](4)

  if key_id.nil?
    puts "✗ Failed to find generated RSA key ID"
    exit 1
  end

  puts "✓ Generated RSA key with ID: #{key_id}"
  [key_id, temp_dir]
end

def generate_ecc_key(name, curve)
  puts "\n🔑 Generating ECC (#{curve}) key pair..."

  temp_dir = "#{TEMP_DIR}/#{name}"
  FileUtils.mkdir_p(temp_dir)
  FileUtils.chmod(0700, temp_dir)

  # Generate key with batch mode
  batch_file = "#{temp_dir}/batch.txt"
  File.write(batch_file, <<~BATCH)
    %echo Generating ECC key
    Key-Type: eddsa
    Key-Curve: #{curve}
    Name-Real: Test User ECC
    Name-Comment: Generated for pgp-rb tests
    Name-Email: test-ecc@example.com
    Expire-Date: 0
    %no-protection
    %commit
    %echo done
  BATCH

  # Generate key
  run_command("env GNUPGHOME=#{temp_dir} gpg --batch --generate-key #{batch_file}")

  # Get key ID
  output = run_command("env GNUPGHOME=#{temp_dir} gpg --list-secret-keys --with-colons")
  key_id = output.lines.find { |line| line.start_with?('sec:') }&.split(':')&.[](4)

  if key_id.nil?
    puts "✗ Failed to find generated ECC key ID"
    exit 1
  end

  puts "✓ Generated ECC key with ID: #{key_id}"
  [key_id, temp_dir]
end

def export_keys(key_id, temp_dir, private_file, public_file)
  puts "\n📤 Exporting keys..."

  # Export private key
  private_key = run_command("env GNUPGHOME=#{temp_dir} gpg --armor --export-secret-keys #{key_id}")
  File.write("#{FIXTURES_DIR}/#{private_file}", private_key)
  puts "✓ Exported private key to: #{FIXTURES_DIR}/#{private_file}"

  # Export public key
  public_key = run_command("env GNUPGHOME=#{temp_dir} gpg --armor --export #{key_id}")
  File.write("#{FIXTURES_DIR}/#{public_file}", public_key)
  puts "✓ Exported public key to: #{FIXTURES_DIR}/#{public_file}"
end

def cleanup
  FileUtils.rm_rf(TEMP_DIR)
  puts "\n🧹 Cleaned up temporary directory"
end

def main
  puts "🚀 PGP Test Key Generator for pgp-rb"
  puts "======================================"

  check_gpg_installed
  setup_temp_dir
  setup_fixtures_dir

  KEYS.each do |key_config|
    puts "\n" + "="*50
    puts "Generating #{key_config[:name].upcase} key pair"
    puts "="*50

    key_id, temp_dir = case key_config[:type]
                       when "rsa"
                         generate_rsa_key(key_config[:name], key_config[:size])
                       when "eddsa"
                         generate_ecc_key(key_config[:name], key_config[:curve])
                       else
                         puts "✗ Unknown key type: #{key_config[:type]}"
                         exit 1
                       end

    export_keys(key_id, temp_dir, key_config[:private_file], key_config[:public_file])
  end

  cleanup

  puts "\n🎉 SUCCESS! All test keys generated and placed in #{FIXTURES_DIR}/"
  puts "\nGenerated files:"
  KEYS.each do |key_config|
    puts "  - #{key_config[:private_file]} (private key)"
    puts "  - #{key_config[:public_file]} (public key)"
  end

  puts "\nYou can now run the tests with: bundle exec rspec"
end

if __FILE__ == $0
  main
end
