{ config, lib, pkgs, ... }:

let 
  cfg = config.services.solanum-rss;
  
  # Derive OAuth configuration from serverPublicUrl if not explicitly set
  effectiveClientId = 
    if cfg.oauth.clientId != null then cfg.oauth.clientId
    else if cfg.settings.serverPublicUrl != null then "${cfg.settings.serverPublicUrl}/client-metadata.json"
    else null;
  
  effectiveRedirectUri = 
    if cfg.oauth.redirectUri != null then cfg.oauth.redirectUri
    else if cfg.settings.serverPublicUrl != null then "${cfg.settings.serverPublicUrl}/oauth/callback"
    else null;
in {
  options.services.solanum-rss = {
    enable = lib.mkEnableOption "Solanum ATProto RSS feed aggregator service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./default.nix { }";
      description = "The solanum package to use.";
    };

    settings = {
      port = lib.mkOption {
        type = lib.types.port;
        default = 8080;
        description = "Port on which the solanum server listens.";
      };

      logLevel = lib.mkOption {
        type = lib.types.enum [ "debug" "info" "warn" "error" ];
        default = "info";
        description = "Log level for the solanum server.";
      };

      logFormat = lib.mkOption {
        type = lib.types.enum [ "pretty" "json" ];
        default = "json";
        description = "Log format. Use 'json' for production, 'pretty' for development.";
      };

      serverPublicUrl = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Public URL for reverse proxy deployments.
          For example: https://solanum.example.com
          
          If set, this will be used for OAuth configuration unless explicit oauth options are provided.
          If not set, localhost URLs will be used (suitable for development).
        '';
        example = "https://solanum.example.com";
      };
    };

    oauth = {
      clientId = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          OAuth client ID. This is typically your server's public URL with /client-metadata.json.
          For example: https://solanum.example.com/client-metadata.json
          
          If not set, will be automatically derived from serverPublicUrl as {serverPublicUrl}/client-metadata.json.
          If serverPublicUrl is also not set, the application will use localhost defaults for development.
        '';
        example = "https://solanum.example.com/client-metadata.json";
      };

      redirectUri = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          OAuth redirect URI. This is where users are redirected after authentication.
          For example: https://solanum.example.com/oauth/callback
          
          If not set, will be automatically derived from serverPublicUrl as {serverPublicUrl}/oauth/callback.
          If serverPublicUrl is also not set, the application will use localhost defaults for development.
        '';
        example = "https://solanum.example.com/oauth/callback";
      };
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/solanum-rss";
      description = "Directory where solanum stores its data (database, OAuth sessions, etc.).";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "solanum-rss";
      description = "User account under which solanum runs.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "solanum-rss";
      description = "Group under which solanum runs.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the firewall for the solanum port.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = lib.mkIf (cfg.user == "solanum-rss") {
      isSystemUser = true;
      group = cfg.group;
      description = "Solanum service user";
      home = cfg.dataDir;
      createHome = true;
    };

    users.groups.${cfg.group} = lib.mkIf (cfg.group == "solanum-rss") { };

    systemd.services.solanum-rss = {
      description = "Solanum ATProto RSS Feed Aggregator Service";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/solanum";
        Restart = "on-failure";
        RestartSec = "10s";

        # Security hardening
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ cfg.dataDir ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        CapabilityBoundingSet = "";
      };

      environment = {
        PORT = toString cfg.settings.port;
        LOG_LEVEL = cfg.settings.logLevel;
        LOG_FORMAT = cfg.settings.logFormat;
        DB_PATH = "${cfg.dataDir}/solanum.db";
      } // lib.optionalAttrs (cfg.settings.serverPublicUrl != null) {
        SERVER_PUBLIC_URL = cfg.settings.serverPublicUrl;
      } // lib.optionalAttrs (effectiveClientId != null) {
        OAUTH_CLIENT_ID = effectiveClientId;
      } // lib.optionalAttrs (effectiveRedirectUri != null) {
        OAUTH_REDIRECT_URI = effectiveRedirectUri;
      };
    };

    networking.firewall =
      lib.mkIf cfg.openFirewall { allowedTCPPorts = [ cfg.settings.port ]; };
  };
}
