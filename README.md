# nix-sigstop

Stop the nix process when waiting for IFD builds to have the kernel prefer it for swapping memory.

## Usage

Just run nix-sigstop in place of nix.
It spawns nix and forwards all arguments.

Makes most sense for `nix eval` but works for any command.

## Why?

Because nix does not have parallel evaluation, it has to wait for each import-from-derivation (IFD) build to complete before it can continue evaluating.
Those IFD builds can take a while. While waiting, the memory nix is using is naturally not available for other use.

This becomes a problem when you are running many memory-hungry evaluations with many IFDs at the same time on one machine.

Hydra has a star-shaped architecture: Only one machine evaluates jobs and distributes them to the build farm.
This can quickly lead to out-of-memory crashes as the OOM killer kills memory-hungry eval processes.

What if we could free up the eval memory while we are just waiting for IFDs to finish?

By putting the nix process into a stopped state, the kernel will move its memory pages to SWAP when memory becomes scarce.

That allows us to run more nix evaluations concurrently as they take turns switching between main memory and SWAP!

## How?

nix-sigstop is a wrapper for nix that keeps track of IFD builds and sends `SIGSTOP` to the nix client process when it is just waiting for them to finish,
and `SIGCONT` once the IFD builds are done so that nix continues to evaluate.

It does so by registering itself as `build-hook` (not to be confused with `pre-build-hook`, see `man nix.conf`) so that it is notified of every started build.
Then it delegates to the actual build hook and notifies the wrapper process once the build is done so that it can continue the nix process.

Here is the flow in a bit more detail:

1. The wrapper sets up
	- a FIFO for IPC and
	- a unix socket for proxying and buffering communication between the nix client and daemon.
2. The wrapper spawns the nix process
	- pointing it to talk do its daemon proxy socket via `--store` and
	- setting itself as `--build-hook` to get notified of builds and
	- passes some needed info to itself as build hook via `--builders`.
3. The nix client starts the evaluation and tells the nix daemon to start a build.
4. The nix daemon starts nix-sigstop as a build hook.
5. nix-sigstop as build hook spawns the actual build hook and proxies the communication between it and the nix daemon.
6. When the actual build hook accepts or declines a build, it spawns a daemon that waits for the build to finish by acquiring locks of all the build's output paths and notifies the wrapper via the FIFO.
7. The wrapper is notified of the first started build and sends `SIGSTOP` to the nix client.
8. While the nix client is stopped, any messages the nix daemon sends into the proxy socket are buffered.
9. The wrapper is notified of the last finished build and sends `SIGCONT` to the nix client.
10. The nix client catches up on all the buffered messages from the nix daemon.
11. When the nix client exits, the wrapper shuts down.

## Caveats

This only works with local daemon stores, which is what most people probably use. The wrapper will complain if you are using an incompatible store.

When running as root, pass `--store daemon` so that nix does not resolve the `auto` store to `local`, attempting to skip the daemon by running the builds itself.
We need nix to do builds via the daemon because stopping the nix process that manages the builds and talks to build hooks leads to a deadlock.

Of course, if you are unlucky and all nix eval processes are done waiting for IFDs and want to actually evaluate at the same time, they will still get OOM killed.
