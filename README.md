# About

Emulite is an emulation framework for Android native libraries, inspired by [Unidbg](https://github.com/zhkl0228/unidbg). iOS support is planned.

> [!WARNING]
> Emulite is an early release. Breaking API changes may occur in future releases, and bugs should be expected.

## Requirements

- Python 3.10+
- Unicorn 2.1.4+
- Capstone 5+
- LIEF 0.14+
- Cryptography 42+

## Installation

From PyPI:

```console
python -m pip install emulite
```

From source:

```console
git clone https://github.com/retrowave3/emulite.git
cd emulite
python -m pip install -e .
```

## Project Status

### Supported Platforms
| Platform | ARM32 | ARM64 |
|----------|:-----:|:-----:|
| Android  | ✅ AndroidEmulator32 | ✅ AndroidEmulator64 |
| iOS      | — | ⏳ |

### Supported Engines
| Backend Engine | Status |
|----------|:-----:|
| Unicorn  | ✅ |
| Dynarmic  | — |
| Apple Silicon Hypervisor  | — |
| Linux KVM Hypervisor  | — |


<sub>✅ Supported · ⏳ Planned · — Not planned</sub>

## Examples

See the [examples](./examples) directory.

## Android Usage

Use `AndroidEmulator32` or `AndroidEmulator64` based on the target architecture. A default Android rootfs is included. Pass a path as the first argument to use a custom rootfs.

```python
from emulite import AndroidEmulator64, HookStatus, LogCategory, JniHandler

class CustomJniHandler(JniHandler):
    # Unhandled methods raise `NotImplementedError`.
    def call_static_method(self, method, args):
        if method.java_class.name == "com/example/Device" and method.name == "getValue":
            return "value"
        return super().call_static_method(method, args)


def before_malloc(emu):
    print("malloc size:", emu.arg(0))


def after_malloc(emu):
    print("malloc returned:", hex(emu.ret))


def before_time(emu):
    replacement_value = 150000
    # emu.set_arg(0, replacement_value)   # Store result in r0/x0
    emu.finish(replacement_value)
    return HookStatus.SKIP_ORIGINAL     # Skip the original call


def on_instruction(emu, info):
    print(info.format())


with AndroidEmulator64(jni_handler=CustomJniHandler(), log=LogCategory.NONE) as emu:
    # Load the target ELF and its dependencies
    module = emu.load("path/to/libnative.so")

    # Hook malloc import
    malloc_hook = emu.hook_symbol(
        "malloc",
        before_malloc,
        after_malloc,
        module_name=module.name,    # Module name is optional
    )

    # Replace time() result
    time_hook = emu.hook_symbol(
        "time",
        before_time,
        module_name=module.name,    # Module name is optional
    )

    # Run JNI_OnLoad
    emu.call_jni_onload(module)

    # Call JNI function
    native = emu.java_class("com/example/Native")
    result = native.call("getValue", "(I)I", 123)

    # Trace executed instructions within the target module
    trace = emu.trace_module(on_instruction, module.name)
    result = native.call("getValue", "(I)I", 123)
    trace.close()

    malloc_hook.close()
    time_hook.close()

    # Allocate memory
    buffer = emu.malloc(32)
    buffer.write_cstr("testing")
    print(buffer.read_cstr())
    emu.free(buffer)

    # Call a regular ELF export by name
    result = module.call_symbol("exported_symbol", 123)
```

## Contributing

Bug reports and pull requests are welcome.

## Resources

- [Unidbg](https://github.com/zhkl0228/unidbg)
- [Unicorn](https://github.com/unicorn-engine/unicorn)
- [LIEF](https://github.com/lief-project/LIEF)
- [Capstone](https://github.com/capstone-engine/capstone)
