{
  perSystem = {inputs', ...}: {
    devShells.default = inputs'.utils.devShells.zig;
  };
}
