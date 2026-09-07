# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "hide-protocol"
  spec.version = "0.5.0"
  spec.summary = "Experimental hybrid post-quantum file and message encryption. Unaudited."
  spec.description =
    "Ruby bindings to the HIDE core (X25519 + ML-KEM-768). Experimental and " \
    "unaudited: a successful decryption proves the data was not altered, not " \
    "who created it."
  spec.authors = ["HIDE contributors"]
  spec.license = "Apache-2.0"
  spec.homepage = "https://github.com/hide-protocol/hide"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  # fiddle is stdlib, so there is no native build step and no runtime gem
  # dependency; the compiled core is copied in by the release workflow.
  spec.required_ruby_version = ">= 3.0"

  spec.files =
    Dir["lib/**/*.rb"] +
    Dir["lib/hide_protocol/*.{so,dylib,dll}"] +
    ["README.md"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
end
