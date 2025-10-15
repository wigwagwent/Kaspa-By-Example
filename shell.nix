let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  buildInputs = with pkgs; [
    rustup

    # OpenSSL dependencies
    pkg-config
    openssl
    openssl.dev
  ];

  RUST_BACKTRACE = 1;

  shellHook = ''
    # Initialize rustup and install components
    rustup default 1.85.0
    rustup component add rust-src rust-analyzer rustfmt clippy
  '';
}

