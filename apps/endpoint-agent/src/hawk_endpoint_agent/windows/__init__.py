"""Reversible Windows endpoint deployment primitives."""

from .command import CommandResult, CommandRunner, WindowsDeploymentError
from .routing import WindowsRouting
from .service import WindowsService
from .state import InstallStateStore, WindowsInstallState
from .trust import WindowsTrust
from .managed_installer import (
    ManagedInstallRequest,
    ManagedInstallResult,
    WindowsManagedInstaller,
)
from .native_driver import (
    NativeDriverInstallResult,
    WindowsNativeDriver,
    WindowsNativePackage,
)
from .kernel_channel import WindowsKernelChannel, WindowsKernelPolicyStatus
from .policy_compiler import (
    CompiledWindowsPolicy,
    WindowsFloorPolicyManager,
    WindowsFloorReconcileResult,
    compile_windows_policy,
    windows_binary_identity,
    windows_kernel_file_identity,
    windows_kernel_network_destination,
    windows_path_identity,
)

__all__ = [
    "CommandResult",
    "CommandRunner",
    "InstallStateStore",
    "WindowsDeploymentError",
    "WindowsInstallState",
    "WindowsRouting",
    "WindowsService",
    "WindowsTrust",
    "ManagedInstallRequest",
    "ManagedInstallResult",
    "NativeDriverInstallResult",
    "WindowsManagedInstaller",
    "WindowsNativeDriver",
    "WindowsNativePackage",
    "CompiledWindowsPolicy",
    "WindowsFloorPolicyManager",
    "WindowsFloorReconcileResult",
    "WindowsKernelChannel",
    "WindowsKernelPolicyStatus",
    "compile_windows_policy",
    "windows_binary_identity",
    "windows_kernel_file_identity",
    "windows_kernel_network_destination",
    "windows_path_identity",
]
