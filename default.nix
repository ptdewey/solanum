{ lib, buildGoModule }:

buildGoModule {
  pname = "solanum";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-FlxtNVM28QB09dgL7VJLU3gJs5wA02EajQ1jWZmZLhs=";

  # nativeBuildInputs = [ tailwindcss_4 ];
  # preBuild = ''
  #   tailwindcss -i static/css/style.css -o static/css/output.css --minify
  # '';

  buildPhase = ''
    runHook preBuild
    go build -o solanum cmd/solanum/main.go
    runHook postBuild
  '';

  installPhase = let
    wrapperScript = ''
      #!/bin/sh
      SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
      SHARE_DIR="$SCRIPT_DIR/../share/solanum"

      # Set default database path if not specified
      # Uses XDG_DATA_HOME or falls back to ~/.local/share
      if [ -z "$SOLANUM_DB_PATH" ]; then
          DATA_DIR="''${XDG_DATA_HOME:-$HOME/.local/share}/solanum"
          mkdir -p "$DATA_DIR"
          export SOLANUM_DB_PATH="$DATA_DIR/solanum.db"
      fi

      cd "$SHARE_DIR"
      exec "$SCRIPT_DIR/solanum-unwrapped" "$@"
    '';
  in ''
        mkdir -p $out/bin
        mkdir -p $out/share/solanum

        # Copy static files and templates
        cp -r public/static $out/share/solanum/
        cp -r public/templates $out/share/solanum/
        cp solanum $out/bin/solanum-unwrapped
        cat > $out/bin/solanum <<'WRAPPER'
    ${wrapperScript}
    WRAPPER
        chmod +x $out/bin/solanum
  '';

  meta = with lib; {
    description = "Solanum - Coffee brew tracker";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "solanum";
  };
}
