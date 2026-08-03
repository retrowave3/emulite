# Emulite

[![PyPI](https://img.shields.io/pypi/v/emulite)](https://pypi.org/project/emulite/)
[![Python](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fpypi.org%2Fpypi%2Femulite%2Fjson&query=%24.info.requires_python&label=python)](https://pypi.org/project/emulite/)

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
pip install emulite
```

From source:

```console
git clone https://github.com/retrowave3/emulite.git
cd emulite
pip install -e .
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

Every hook returns a `HookHandle`; call `unhook()` when the hook is no longer needed. Handles can also be used as context managers when lexical scoping is convenient. Replacement, trace, and memory callbacks use explicit action enums, so callback behavior is visible in both code and type checkers.

```python
from emulite import AndroidEmulator64, AndroidEmulatorBase, JniHandler, JniValue, LogCategory, MemoryAccess, MemoryHookAction, ReplacementAction, TraceAction, TraceInfo
from emulite.android.java.lang.reflect.java_method import JavaMethod


class CustomJniHandler(JniHandler):
    # Unhandled methods raise `NotImplementedError`.
    def call_static_method(self, method: JavaMethod, args: list[object]) -> JniValue:
        if method.java_class.name == "com/example/Device" and method.name == "getValue":
            return "value"
        return super().call_static_method(method, args)


def before_malloc(emu: AndroidEmulatorBase) -> ReplacementAction:
    print("malloc size:", emu.get_argument(0))
    return ReplacementAction.CALL_ORIGINAL


def after_malloc(emu: AndroidEmulatorBase) -> None:
    print("malloc returned:", hex(emu.get_return_value()))


def replace_time(emu: AndroidEmulatorBase) -> ReplacementAction:
    emu.set_return_value(150000)
    return ReplacementAction.SKIP_ORIGINAL


def on_instruction(_emu: AndroidEmulatorBase, info: TraceInfo) -> TraceAction:
    print(info.format())
    return TraceAction.CONTINUE


def on_memory(_emu: AndroidEmulatorBase, access: MemoryAccess, address: int, size: int, value: int) -> MemoryHookAction:
    print(access.name.lower(), hex(address), size, hex(value))
    return MemoryHookAction.CONTINUE


emu = AndroidEmulator64(jni_handler=CustomJniHandler(), log=LogCategory.NONE)

# Load the target ELF and its dependencies
module = emu.load("path/to/libnative.so")

# Run JNI_OnLoad
emu.call_jni_onload(module)

# Call a registered static JNI method
native = emu.java_class("com/example/Native")
result = native.call("getValue", "(I)I", 123)

# Observe malloc before and after the real function runs
malloc_hook = emu.hook_symbol("malloc", before_malloc, after_malloc, module_name=module.name)
result = native.call("getValue", "(I)I", 123)
malloc_hook.unhook()

# Replace time() without calling the original function
time_hook = emu.hook_symbol("time", replace_time, module_name=module.name)
result = native.call("getValue", "(I)I", 123)
time_hook.unhook()

# Trace instructions from the target module
trace = emu.trace_module(on_instruction, module.name)
result = native.call("getValue", "(I)I", 123)
trace.unhook()

# Allocate typed guest memory and observe native access to it
buffer = emu.malloc(32)
buffer.write_cstr("testing")
print(buffer.read_cstr())

watchpoint = emu.watchpoint(int(buffer), on_memory, length=32)
result = module.call_symbol("exported_symbol", int(buffer))
watchpoint.unhook()

emu.free(buffer)
emu.close()
```

## Contributing

Bug reports and pull requests are welcome.

## Resources

- [Unidbg](https://github.com/zhkl0228/unidbg)
- [Unicorn](https://github.com/unicorn-engine/unicorn)
- [LIEF](https://github.com/lief-project/LIEF)
- [Capstone](https://github.com/capstone-engine/capstone)
