# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "hide-protocol"
  spec.version = "0.9.1"
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
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "documentation_uri" => "#{spec.homepage}/blob/main/sdk/ruby/README.md",
    "rubygems_mfa_required" => "true"
  }

  # The publish workflow copies the compiled core in and sets
  # HIDE_GEM_PLATFORM, so `gem install` fetches only this machine's binary and
  # there is no native build step. Without it the gem still builds, as a
  # source gem needing HIDE_LIBRARY.
  platform = ENV["HIDE_GEM_PLATFORM"]
  spec.platform = platform unless platform.nil? || platform.empty?

  spec.required_ruby_version = ">= 3.0"

  # The gemspec itself is shipped: the binding reads its own version from it
  # at load time, to refuse a native library from a different release.
  spec.files =
    Dir["lib/**/*.rb"] +
    Dir["lib/hide_protocol/*.{so,dylib,dll}"] +
    Dir["{README.md,LICENSE,hide-protocol.gemspec}"]
  spec.require_paths = ["lib"]

  # fiddle is a default gem up to Ruby 3.4 and a bundled gem from Ruby 4.0,
  # where a Bundler-managed application can only require what its bundle
  # declares.
  # 1.0.6 is the version Ruby 3.0.0 ships, and has everything the binding
  # uses, so no supported Ruby has to compile a newer fiddle to satisfy this.
  spec.add_dependency "fiddle", ">= 1.0.6"

  spec.add_development_dependency "minitest", "~> 5.0"
end
