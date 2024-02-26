# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pgp-rb/version'

Gem::Specification.new do |spec|
  spec.name = 'pgp-rb'
  spec.version = PGP::VERSION
  spec.summary = 'rPGP ruby wrapper'
  spec.files = Dir['lib/**/*.rb', 'ext/**/*.{rs,toml,lock,rb}']
  spec.extensions = ['ext/pgprb/extconf.rb']
  spec.rdoc_options = ['--main', 'README.rdoc', '--charset', 'utf-8', '--exclude', 'ext/']
  spec.authors = ['Kirill Zaitsev']
  spec.email = ['kirik910@gmail.com']
  spec.homepage = 'https://some'
  spec.license = 'Apache'

  spec.requirements = ['Rust >= 1.61']
  spec.required_ruby_version = '>= 3.0.0'

  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake-compiler', '~> 1.2'
  spec.add_development_dependency 'rb_sys', '~> 0.9'
  spec.add_development_dependency 'rspec', '~> 3.13'
  spec.add_development_dependency 'rubocop'
end
