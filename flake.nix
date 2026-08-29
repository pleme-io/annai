{
  description = "annai (案内) — the fleet stub resolver: answer from a typed name table, forward the rest";

  # Canonical pleme-io Rust-tool consumer flake. substrate.rust.tool pre-binds
  # nixpkgs / crate2nix / flake-utils / fenix / devenv / gen, so a substrate bump
  # propagates fleet-wide without touching this file.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.tool {
    src = ./.;
    member = "annai";
    module = {
      description = "annai (案内) — the fleet stub resolver";
    };
  };
}
