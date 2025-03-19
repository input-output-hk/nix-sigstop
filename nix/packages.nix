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

        zigDepsHash = "sha256-dZgP6viar2Wp+CfgkZVF+owCiOIeeLlbMQXBGiJHjfI=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
