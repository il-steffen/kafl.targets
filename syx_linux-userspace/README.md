# SYX Linux x86_64 userspace example target

This example shows how a simple userspace fuzzer could be implemented to make use of SYX.

There are two main files involved:
- `loader.c`: The boilerplate code responsible for setuping the target. It basically communicates with the hypervisor and loops over the target function.
- `targets.c`: The example targets. They are not doing anything interesting but are useful for testing purposes. It also contains the crash function to signal to kAFL a crash happened.

## Configuration

`config.mk` is the main file to configure the targets and the fuzzing session. It is where the target to compile can be selected.
If necessary, it should be easy to edit `fuzz.sh` to customize much more precisely the fuzzer options.

## Build

Simply run:

```bash
make
```

## Fuzz

### Getting a Linux kernel

You will need a Linux guest kernel to run the example. You may find the kernel you are actually running in `/boot` and use it to run this example. Once the kernel is ready, please put the path of the kernel in `config.mk`.

### Run the fuzzer

It is first required to get into the fuzzing environment. Please have a look at [the root repository](https://github.com/IntelLabs/kAFL/) if this point is not clear.

Once the environment is activated, you are ready for fuzzing:

```bash
make fuzz
```

You should be able to use the usual `kafl_*.py` scripts to play around with the results. The workdir can be changed in `config.mk`.