{inputs, ...}: {
  perSystem = {
    config,
    pkgs,
    ...
  }: {
    packages = {
      default = config.packages.nix-sigstop;

      nix-sigstop = pkgs.buildZigPackage {
        src = inputs.inclusive.lib.inclusive ./.. [
          ../build.zig
          ../build.zig.zon
          ../src
        ];

        zigDepsHash = "sha256-njH1sIBzV41de0G86dbSVrpGKaNp/kyMRkXHaTIfjxE=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
