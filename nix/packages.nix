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

        zigDepsHash = "sha256-WEPQFQMr5ANGpZhoTXLYs+Mv/hk6aGYlRavP2sY1vd8=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
