{inputs, ...}: {
  imports = with inputs; [
    make-shell.flakeModules.default
  ];

  perSystem.make-shells.default.imports = [inputs.utils.shellModules.zig];
}
