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

        zigDepsHash = "sha256-JB2gaSv+GI4SzXWSuGjYkgKr8Tx3DdYZJvT3eyu8Bnc=";

        meta.mainProgram = "nix-sigstop";
      };
    };
  };
}
