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

        zigDepsHash = "sha256-//ytKMmFpQQTRZLjOraa20X9TrHNs/G1+pP8D31RHQs=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
