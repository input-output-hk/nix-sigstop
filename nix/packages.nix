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

        zigDepsHash = "sha256-ntgkUR2Va4Y1BU6zWeEBLDNAkGPLp5yN8BqXWClrrM0=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
