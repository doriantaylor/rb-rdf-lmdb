# -*- mode: enh-ruby -*-
lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "rdf/lmdb/version"

Gem::Specification.new do |spec|
  spec.name          = 'rdf-lmdb'
  spec.version       = RDF::LMDB::VERSION
  spec.authors       = ['Dorian Taylor']
  spec.email         = ['code@doriantaylor.com']
  spec.license       = 'Apache-2.0'
  spec.homepage      = 'https://github.com/doriantaylor/rb-rdf-lmdb'
  spec.summary       = 'Symax LMDB back-end for RDF::Repository'
  spec.description   = <<-DESC
This module implements RDF::Repository on top of LMDB, a fast and
robust key-value store.
  DESC
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features)/})
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # ruby
  spec.required_ruby_version = '~> 2.0'

  # dev/test dependencies
  spec.add_development_dependency 'bundler',  '~> 2.0'
  spec.add_development_dependency 'rake',     '~> 13.0'
  spec.add_development_dependency 'rspec',    '~> 3.0'
  spec.add_development_dependency 'rdf-spec', '~> 3.0'

  # stuff we use
  spec.add_runtime_dependency 'unf',  '~> 0.1.3'
  spec.add_runtime_dependency 'rdf',  '~> 3.1'
  spec.add_runtime_dependency 'lmdb', '~> 0.5.2'
end
