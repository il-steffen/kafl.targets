# Linux x86_64 userspace example target

This example shows how a simple userspace fuzzer could be implemented.

There are two main files involved:
- `loader.c`: The boilerplate code responsible for setuping the target. It basically communicates with the hypervisor and loops over the target function.
- `target.c`: The example target. It is a very simple code doing dummy things. It also contains the crash function to signal to kAFL a crash happened. 

## Build

Simply run:

```bash
make
```

## Fuzz

### Getting a Linux kernel

You will need a Linux guest kernel to run the example. You may find the kernel you are actually running in `/boot` and use it to use this example. Once the kernel is ready, please put the path of the kernel in `config.mk`.

## Configuring the fuzzing session

`config.mk` provides a nice way to configure basic fuzzing options. If necessary, it should be easy to edit `fuzz.sh` to customize much more precisely the fuzzer.

### Run the fuzzer

It is first required to get into the fuzzing environment. Please have a look at [the root repository](https://github.com/IntelLabs/kAFL/) if this point is not clear.

Once the environment is activated, you are ready for fuzzing:

```bash
make fuzz
```

The working directory used by default is `workdir`. You should be able to use the usual `kafl_*.py` scripts to play around with the results.