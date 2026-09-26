require "./spec_helper"
require "yaml"

# Garde-fou contre la désynchronisation entre la constante
# `TOTP::VERSION` (lue au compile-time depuis `shard.yml`) et
# la valeur réelle du `version:` du shard.yml.
#
# Si jamais on régresse sur le macro `read_file` dans
# `src/totp/version.cr`, ce spec rouge alerte immédiatement.
#
# Cf. note mémoire `feedback_shard_version_macro.md`.
describe TOTP do
  it "VERSION matche shard.yml (compile-time read, pas de désynchro)" do
    yml = YAML.parse(File.read(File.join(__DIR__, "..", "shard.yml")))
    TOTP::VERSION.should eq(yml["version"].as_s)
  end

  it "VERSION est au format SemVer X.Y.Z (création) ou X.Y.Z.N (portage)" do
    TOTP::VERSION.should match(/^\d+\.\d+\.\d+(\.\d+)?$/)
  end
end
