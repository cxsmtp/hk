#!/usr/bin/env python3
"""Plan and enroll the latest locally installed provider-native controls.

This operator tool deliberately separates three truths:

* exact reviewed native-hook versions may be enrolled for signed monitoring;
* unreviewed or integrity-failed installations remain discovery-only;
* ChatGPT Desktop has no documented native lifecycle-hook contract and is
  therefore represented through Hawk's existing composite discovery view.

No bearer token or private key is written to disk.  The operator signs in at
the terminal, while provider callbacks use fresh Secure Enclave identities.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import os
import shlex
import stat
import json
from pathlib import Path
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from typing import NamedTuple
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_ENV = ROOT / ".env.production"
PRODUCTION_STACK = ROOT / "infra" / "legacy" / "hawk_production_stack.sh"
ENDPOINT_ROOT = Path.home() / "Library/Application Support/Hawk/EndpointAgent"
ENDPOINT_PYTHON = ENDPOINT_ROOT / "runtime/venv/bin/python"
NATIVE_HELPER = ENDPOINT_ROOT / "runtime/bin/hawk-native-hook"
IDENTITY_HELPER = ENDPOINT_ROOT / "runtime/bin/hawk-device-identity"
STATE_ROOT = Path.home() / ".hawk/native-control"


CODEX_SOURCE_SHA256 = {'native_control/hook.py': '18c5faf04ce11fb04b28bbe452fb9c85fa156e25575ccc553a905ef688610994', 'native_control/cli.py': '6b9dd46fd2cd4169596ea1b670b3e7b11d849ba38857e5d11a9429ef3fa17df7', 'native_control/installer.py': '99af4847f1b23290ba3406ab1dd0063072cbcac4b402a3ee165080887b91ba1c'}
CODEX_SITE_SHA256 = {'hawk_endpoint_agent/__init__.py': '682216340ba15ea315a0ab3276034702e5fd668844ac89337c8544e9aae131f4', 'hawk_endpoint_agent/__main__.py': '6e005aa707050dd1fc28abcca5003d4e2daf2e8a1a46f4a6a9247b0b95563c7d', 'hawk_endpoint_agent/agent_registration.py': 'c3adfb6bd1f02e8816b163aaeb2d3c4ee82c7caa3525a6ea5b6ad1aa9b2ee738', 'hawk_endpoint_agent/attestation.py': '18949939bace71d70bdf3cdced78677697b815136baf112a346678299243e5b5', 'hawk_endpoint_agent/auth/__init__.py': 'a3f5ed7ced18edad5e801c7d0277e6b17911a3a7f2dabf1a9b68d58481c82100', 'hawk_endpoint_agent/auth/device_key.py': 'ace1aeb5f5d51a494407b22a9d6244123842d40874dc9e273ae602c7decd1926', 'hawk_endpoint_agent/auth/dpop.py': '836ef8adc96269297e903cc57e8ee7344c60d6eefe06489611de0de19043a25a', 'hawk_endpoint_agent/auth/identity_health.py': 'f44ba0c1a2398ee4a7c960c291cda2d65346922fc3556df366f201c581323b51', 'hawk_endpoint_agent/auth/kms_hsm.py': '5b6769b12c0670f26763f9d0041eaccbf4c7e60cc4c51c08c5001b63c330d99a', 'hawk_endpoint_agent/auth/linux_tpm2.py': '58b57575f759a8fe7fc4313325b37a21006e7581b1320b0b5c8021ee7911af4f', 'hawk_endpoint_agent/auth/memory_vault.py': '2df6da7999021390d85e0f32c7aec98b98b65276a7fe6ea4bfe3b9663a60b187', 'hawk_endpoint_agent/auth/session.py': 'fa05bc28885398c5f62253097905aa7147990eb8427e9d1d1bb059c4d1eb873e', 'hawk_endpoint_agent/auth/windows_tpm.py': '85d205b98542164c28b62dd52718d76c33aff97ae6152cb0b7152a0a78ae434c', 'hawk_endpoint_agent/baseline.py': 'b80a554e9a41dc45bf024b49a9ed187b806db4fbc4ad7caa294bff8eb58df0d6', 'hawk_endpoint_agent/bridge/__init__.py': '0ddde00a92b46351380fa1ce1c48c499d7b5ac5ff62cbffa4d9e9605c2516d39', 'hawk_endpoint_agent/bridge/__main__.py': '0b48c7fc49fb6cf6117111eb39d0e4edb314f2de0e544ad51b467c4e68dbe255', 'hawk_endpoint_agent/bridge/framing.py': '5add3e8e2ccff697d7b43cf53cbebc77ea8e84a3262645db5cd545b95392f83f', 'hawk_endpoint_agent/bridge/host.py': '9d3b72bfd29cae14231dcce2669c185a262ae3015b02982e2759ec17f4340433', 'hawk_endpoint_agent/bridge/manifest.py': 'e038b914e90febdec5d2641ebee232d6ab69a3fd4678f9b97ba54a9602357c4f', 'hawk_endpoint_agent/bridge/socket_client.py': '747e651ff5621cce670e6a2ddae5a757abf5d11baba739357d8802b820be1b07', 'hawk_endpoint_agent/catalog.py': '3f9cb3560212af272c3ebbbec72609a754f9a24faffae2fe7b8880fb565b1cbb', 'hawk_endpoint_agent/chatgpt_desktop.py': '7379e15aaf181f71167ccec097a99e625a27825433754d28d6281b1851f96690', 'hawk_endpoint_agent/collectors/__init__.py': '55abc79ec54d82a0570d36b56e618ba87e1e8602c265a34d0825d457e218d75b', 'hawk_endpoint_agent/collectors/audio.py': 'badf49dcd83de24990c4f7cd810c650aadeeaa5e6a296bb26355ff87de19ca7e', 'hawk_endpoint_agent/collectors/base.py': 'e46a918876a061216b777f905d6d3e8c6d6ce49f5cc4113a6bd98055d3e3b8f4', 'hawk_endpoint_agent/collectors/desktop_apps.py': '2691ce62162607fc51aeaee97e42f07cf87365bf55472d4d3ae6130ec3f71c5e', 'hawk_endpoint_agent/collectors/meetings.py': '865bdb30722109e2240663b47d5b62e3ee94f5717ce045b6dd021d9c381a33e0', 'hawk_endpoint_agent/collectors/network.py': '2d1c18cd43cdf2d70ce66e5334163c165d91aee0d694cf626db032f6180acb61', 'hawk_endpoint_agent/collectors/processes.py': '7cbf6c55568d12f857174d88b74d43ffc50ba3cdc42dbf54059daaad67af03ef', 'hawk_endpoint_agent/config.py': '80f31ef501442e65fb8499b4464be9ba0720c11d050e6ef3c92c1035a22e769d', 'hawk_endpoint_agent/control_plane.py': 'ed576a1d1b79923842e9c989571ab99a0eab017c5ba554e24925a8e641d61afc', 'hawk_endpoint_agent/decision.py': '4cf8db917d15fed73f2598e96df0aff3af69b6975a8d1691a9f5fee289cbd55f', 'hawk_endpoint_agent/dispatcher.py': '793896c4ffff7e0da2ce9ff41ab2a2671318ee04bd0fc2938f9ff7e52eaac11d', 'hawk_endpoint_agent/endpoint_floor/__init__.py': 'b23b5a2d4bff7fc80a135b33f163ca0705a20f5dfc4128ec353d7ee0ca1eeb40', 'hawk_endpoint_agent/endpoint_floor/contracts.py': '2c4940ccba9491cd9299b6e85d5dd995e3e6ad72263e24b8d4dfce2aff6ed920', 'hawk_endpoint_agent/endpoint_floor/correlation.py': 'eee1fe6c57081b312f91972cb460dd1cf15f2499d60b5c73bf48db05d9cc262b', 'hawk_endpoint_agent/endpoint_floor/health.py': 'b343881757ead0eb76a3d9c1c93965867dea032cd6d45b9b93062ec13606bc8c', 'hawk_endpoint_agent/endpoint_floor/local_policy.py': 'da545305fa93fbeaef07b02a9b2da4c4e8ff149d787107ad09f3bdada9c3b23d', 'hawk_endpoint_agent/endpoint_floor/operations.py': '0a095546e0f4a72171ce92f4fc811513b47b8a7c65ef2bb61674460635d40ac4', 'hawk_endpoint_agent/endpoint_floor/permits.py': 'c3b42a732d009e431d35142ae686e65bfc38bd659f40f8a2e8e05ef0c396bda4', 'hawk_endpoint_agent/endpoint_floor/policy_compiler.py': '1be64011bd13fb83bdf1529a586178e193d5aaf77c5c3663a0c0f92f64e22c86', 'hawk_endpoint_agent/endpoint_floor/runtime.py': 'b720c850bade62a464e5230d1aea8b172dc4d5f349f30d461e8010a5527e0067', 'hawk_endpoint_agent/endpoint_floor/taint.py': 'e056dbfc5706965be2c9867ad5e56f155593816caaa4e2e9a75ae9ec0113597e', 'hawk_endpoint_agent/enforcement.py': '09147ffe2e9906f15303aa25807125406c1f7c245624ae0b265359791a8a2f68', 'hawk_endpoint_agent/enforcers/__init__.py': 'b3df43c7c55653e041c2f51af93305c4ee910ddad7c80c84856c885e80654c72', 'hawk_endpoint_agent/enforcers/audio_control.py': '5b15132569ec91308ee6fa07e2b872dcc06714eb4aa1cc0e0091c0e848d12216', 'hawk_endpoint_agent/enforcers/banner.py': '66cb958b3fa3f653e3f44c4f62734e9dc9085169a24325fb680164958c93e297', 'hawk_endpoint_agent/enforcers/meeting_platform_control.py': '8269ddb14919dd2746aa86fe8207460a6f8fdbc225f43674fa030df48350779b', 'hawk_endpoint_agent/enforcers/network_control.py': '78ebb0af25628f62c4061d540e19e8760f5bafecf01fc9ba8d84604d38c70ce4', 'hawk_endpoint_agent/enforcers/process_control.py': '865200cc53ab8b8d956973fab74fc3996b58dde423d7772e30e34dc38afd24a1', 'hawk_endpoint_agent/enroll.py': 'ca5d746bdc6b74d09de4b7335c0bb9b9f4e6510849b2f952e83c75c95a5fd22e', 'hawk_endpoint_agent/evidence_queue.py': '3a3d4258e3cb455a5f5467ee89f25c83111253d5439e51f939dcb5f8986170c6', 'hawk_endpoint_agent/governance_status.py': 'f22159d4e251d716349b77545956db1383eae3c35ba363fcf71df10b5a1444b4', 'hawk_endpoint_agent/hawk_client.py': '65b128709279a1c9ceaeecc0dabdfa13c98f2bb95c6c48feed29ac89e599a4b4', 'hawk_endpoint_agent/hmair_snapshot.py': '9c6516fbd91046bd7fe0830eddb8f13325740f8d496402664c5a156cc7a9cc3f', 'hawk_endpoint_agent/identity.py': '047f910a79397865a275c4773f0caae05917a4d1cb2929099617fc3cab06ef84', 'hawk_endpoint_agent/ipc/__init__.py': 'c1971dbfde3fef3470a098cfd581edd2b2620ad0bb9299713a5395552367be78', 'hawk_endpoint_agent/ipc/control_server.py': 'aaaa49933ac9e4f1efe851fdf97ef79d9956f5ae09f8472b302f521db1ec6dcd', 'hawk_endpoint_agent/legacy_residue.py': '9eaaa8541827b616f70543de1a622baa9748e268bcfee3c751e950d6e237f122', 'hawk_endpoint_agent/local_broker_auth.py': 'b1140772bd45d3069196be60704a2598e144410f3565b914ac75a1d421d19351', 'hawk_endpoint_agent/macos_routing.py': '050e35a11f90890d212ba0a95e6df04a00fd16b6f4a7f9454bc37946e93d8a69', 'hawk_endpoint_agent/metadata_scanner.py': '062478f0c3776eb39051037f3aaf540c8993fb6f874ae07afef93c99808756ae', 'hawk_endpoint_agent/metadata_scanner_cli.py': 'fd26897abdb471a1c6dc6a2b719ffc5b7db5c5a0db640b10337ee679c05d2b22', 'hawk_endpoint_agent/modules/__init__.py': 'ae1241f088c43c12901abfd846887d524b945feb16b45101750191f4efffccbc', 'hawk_endpoint_agent/modules/agent_runtime.py': '5ab3c409d1a81cabdc1980b075861a46fd5c47c28f26950d9860ea77b5ccb5c8', 'hawk_endpoint_agent/modules/data_transfer.py': '6b2c1f0ccf98e3924c24341416799792338e885c2dccfa0ec874154022657219', 'hawk_endpoint_agent/modules/desktop_native.py': 'eb4a7866f7d9c5a5bbace3ca3616964430cb12ac419d0dbdb5a3907e87d49739', 'hawk_endpoint_agent/modules/interaction_security.py': '717cd3008c1ad5f43c677ba7767f2be3af5372576532eb4e6b0a5e85d16d813c', 'hawk_endpoint_agent/modules/notetaker.py': '5f0ccff90c771a8b7678b14a008e3305a3e0f262e75fdecc419b105030ef793c', 'hawk_endpoint_agent/modules/shadow_ai.py': '03e108a8bc67c44fe2af5773b1a4fe026f3bfffde7dca328bb161e7d12f3381f', 'hawk_endpoint_agent/native_control/__init__.py': '29d4854417c0f0562d6556c847127890bd34ccc89517e7f5945940f9bb3056b5', 'hawk_endpoint_agent/native_control/claude_acceptance.py': '466ba403b034795351c5ad80b6d6938935f50c55ba9ece1c7b234026b5ff07b6', 'hawk_endpoint_agent/native_control/claude_mcp_fixture.py': 'a6ab86ddb49df69113bb6650f1f332c813f25977b614fbc36257c89e350bf2c3', 'hawk_endpoint_agent/native_control/cli.py': '6b9dd46fd2cd4169596ea1b670b3e7b11d849ba38857e5d11a9429ef3fa17df7', 'hawk_endpoint_agent/native_control/codex_acceptance.py': '38892b5623b02a93125ab419fdf1dd4583f7c95e7a5bcce132d65c953ccf9c5c', 'hawk_endpoint_agent/native_control/cursor_acceptance.py': '299916ca48ec0dde2b616ed1bbb83f3e1519f2772ca63504ffc6dd3a12f32088', 'hawk_endpoint_agent/native_control/endpoint_permit_binding.py': '358a14e46e69ea7e602d6e595a2a469682087d270e94e0a4a288fc5c00c81c43', 'hawk_endpoint_agent/native_control/gemini_acceptance.py': 'ffd51917e571195d0bfe97bce1633d11dc5b62d5468617c8386028651a665582', 'hawk_endpoint_agent/native_control/gemini_mcp_fixture.py': '3a231396fc7a2a24d9af973949bc7ffecba83be2f4ca51107c99ac77f1265e15', 'hawk_endpoint_agent/native_control/gemini_serializer.py': 'a90da623a6f7f4caaa9e61580d8ed0882916d34f87db5a322ccc56430d3382c6', 'hawk_endpoint_agent/native_control/hook.py': '18c5faf04ce11fb04b28bbe452fb9c85fa156e25575ccc553a905ef688610994', 'hawk_endpoint_agent/native_control/installer.py': '99af4847f1b23290ba3406ab1dd0063072cbcac4b402a3ee165080887b91ba1c', 'hawk_endpoint_agent/operator_cli.py': '1f809eec8e419976e0a471719c85c5ac1a0b8d8a2857e2e0459717011c12eeef', 'hawk_endpoint_agent/policy.py': 'af76e751d0b3c1347117795281515a26e66dd13dfac1a322cb64947167403521', 'hawk_endpoint_agent/privacy.py': 'f140831d1e5083d1d5830ff2d684668faa041a10e68c89639d96f05841e3c5af', 'hawk_endpoint_agent/proxy/__init__.py': '88ca7e38150a1789301245dcd7cb098e2c3516974e42aa6665dc5764aa9d0134', 'hawk_endpoint_agent/proxy/classifier.py': 'dfed76713c14fb3b35525114d621ca7ec3ad27bab5a495e7619026ca2caf68db', 'hawk_endpoint_agent/proxy/local_proxy.py': '049262c9200a2078d87d04b12aa8dd9f57406283225351fcc168c8643a6ab4ba', 'hawk_endpoint_agent/resource_governor.py': '672d83a5825b08844ad97bc55f424ff9ecce8869fc833dc544c3fd32185fc252', 'hawk_endpoint_agent/resources/__init__.py': 'b6c550eff594d308a0993acdad9a7d08ba7ae7b9fb2589661a895491f083c582', 'hawk_endpoint_agent/resources/windows_audio_sessions.ps1': '305b3ffef5573eef57566a1d0b67fabd8e27e4e5911af93ffa17ce01fb120c8b', 'hawk_endpoint_agent/runner.py': '7fccad37947301076717ea01343336a53f8063274ae6288b09e694dbf4bd50d6', 'hawk_endpoint_agent/signals.py': 'b3aaa7ee0b3a6a258fa38a87af41b6ae28f185e624b924bc18544bbe4cef3f8f', 'hawk_endpoint_agent/surfaces.py': 'a6cfbf8ba39ef8d018c4eeeac256c7a379612f730cdca451332b750fba95cef9', 'hawk_endpoint_agent/tls/__init__.py': 'f53a5e0f138a3ab905af77deb33b1481aa5d6535d07e533d4a9df161a2d2ea15', 'hawk_endpoint_agent/tls/certs.py': '19aca03cc847cf214e58e2fa0b6de4f0228a38562a7435139645f30df154dde2', 'hawk_endpoint_agent/tls/interceptor.py': '0ff14adfa8731ee03d02c84aed250259c847b596a00d49decbf8a9760486c027', 'hawk_endpoint_agent/windows/__init__.py': '6ace32bcb7d8cae238413389b2a146794efb66fac11f6e4181aad1e341b37852', 'hawk_endpoint_agent/windows/command.py': '65fde12d5ad15d9f8ff4f3103d4f9e4a9b29ab0b51db570b463b571ba2a002b7', 'hawk_endpoint_agent/windows/kernel_channel.py': '3ca50914c2d37aca17f037c08444c8cc70a14eac39dc97e72eac882751e5d899', 'hawk_endpoint_agent/windows/managed_installer.py': '7134cfa15a652ee3a44d0ea7d9f3793b1378beba811d1425326c2332ae53a363', 'hawk_endpoint_agent/windows/native_driver.py': '7373debeb4b1f7df1025bee57ad779246340fcd358972acdf35a8ccb3cb29356', 'hawk_endpoint_agent/windows/policy_compiler.py': 'a0ddbdf7d5443d9319ce9a7fe9553b808ccfa9d6edd4df6488386ae30f3d78d6', 'hawk_endpoint_agent/windows/routing.py': 'cb902f6b34c4462468fce4d6c5ca1654f7620514ece6f2290d70a5ae0b52826d', 'hawk_endpoint_agent/windows/service.py': 'c4eb6452218eeb778f24684ee0137bb3551aa192ba8d9a6074cde81383875959', 'hawk_endpoint_agent/windows/state.py': 'f0f930c10b5ec6d2fff15a30935bfa15a330a5e760f205165537d99e79429ba2', 'hawk_endpoint_agent/windows/trust.py': '93d19744145d406d7ad9a5fd085a4d67fec2b714fab7ebd107f5fdb36d26cf5b', 'hawk_endpoint_agent/windows_metadata_scanner.py': '5eef3af99a62fc627eab2207b8f37d9f2e6ef8dc7b4acc669984c9c18b2d847f', 'hawk_endpoint_agent-0.2.1.dist-info/METADATA': '93d6cf9262b278451434dc98bc0830a70edf62313632bdedcdc19f86e77d7ba1', 'hawk_endpoint_agent-0.2.1.dist-info/RECORD': 'b45b64414625c97afc289e1170c9a76b2f9198193205c369a1d2c5f89c824711', 'hawk_endpoint_agent-0.2.1.dist-info/WHEEL': '61532836a2b3111b7ec23519c09df7c41180c27165fb872a6d8913b566b88ad1', 'hawk_endpoint_agent-0.2.1.dist-info/entry_points.txt': 'a2d63a50811da73b07aa1309f75ba644a90be5bf1b4fec322dc121253a28bc45', 'hawk_endpoint_agent-0.2.1.dist-info/top_level.txt': 'e89d42eaa045819f2f0ad90c3476cbed8af05b3c1e497113c4881b8db772ca8d'}
IDENTITY_HELPER_SHA256 = "20fb31ecab7dfc625fecf70b1bdf77e05bf108031068a7644105ddfb788b7730"


class CodexRuntime(NamedTuple):
    root: Path
    site: Path
    python: Path
    helper: Path
    cli: Path
    bootstrap: Path
    identity: Path


def codex_runtime_bootstrap() -> str:
    return "import hashlib, importlib, json, runpy, sys\nfrom pathlib import Path\nsite = Path(__file__).resolve().parent / 'site'\npinned = " + repr(CODEX_SITE_SHA256) + "\npaths = list(site.rglob('*'))\nif any(path.is_symlink() for path in paths):\n    raise SystemExit('codex_runtime_integrity_invalid')\nactual = {str(path.relative_to(site)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.is_file()}\nif actual != pinned:\n    raise SystemExit('codex_runtime_site_mismatch')\nsys.path.insert(0, str(site))\ncomponent = sys.argv.pop(1)\nif component == 'smoke':\n    modules = [importlib.import_module('hawk_endpoint_agent.native_control.' + name) for name in ('hook', 'cli', 'installer')]\n    if not all(Path(module.__file__).resolve().is_relative_to(site.resolve()) for module in modules):\n        raise SystemExit('codex_runtime_import_mismatch')\n    print('candidate_isolated_imports_confined')\nelif component in ('hook', 'cli'):\n    runpy.run_module('hawk_endpoint_agent.native_control.' + component, run_name='__main__')\nelse:\n    raise SystemExit('codex_runtime_component_invalid')\n"


def codex_runtime_wrapper(root: Path, python: Path, component: str = "hook") -> str:
    if component not in {"hook", "cli"}:
        raise RuntimeError("codex_runtime_component_invalid")
    return '#!/bin/sh\nexec ' + shlex.quote(str(python.resolve(strict=True))) + ' -I -B ' + shlex.quote(str(root / "bootstrap.py")) + ' ' + component + ' "$@"\n'


def validate_codex_runtime(root: Path) -> CodexRuntime:
    root = root.absolute()
    def owned(path: Path, *, directory: bool = False, executable: bool = False):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise RuntimeError("codex_runtime_integrity_invalid")
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise RuntimeError("codex_runtime_integrity_invalid")
        if executable and not os.access(path, os.X_OK):
            raise RuntimeError("codex_runtime_integrity_invalid")
    if root.resolve() != root:
        raise RuntimeError("codex_runtime_integrity_invalid")
    owned(root, directory=True)
    site, helper, cli, bootstrap = root / "site", root / "bin/hawk-native-hook", root / "bin/hawk-native-control", root / "bootstrap.py"
    owned(site, directory=True)
    owned(root / "bin", directory=True)
    for path in site.rglob("*"):
        owned(path, directory=path.is_dir())
    actual = {str(path.relative_to(site)): hashlib.sha256(path.read_bytes()).hexdigest() for path in site.rglob("*") if path.is_file()}
    if actual != CODEX_SITE_SHA256:
        raise RuntimeError("codex_runtime_site_mismatch")
    owned(helper, executable=True)
    owned(cli, executable=True)
    owned(bootstrap)
    if bootstrap.read_text() != codex_runtime_bootstrap():
        raise RuntimeError("codex_runtime_bootstrap_mismatch")
    owned(root / "release-manifest.json")
    interpreter = ENDPOINT_PYTHON.resolve(strict=True)
    info = interpreter.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or not os.access(interpreter, os.X_OK):
        raise RuntimeError("codex_runtime_interpreter_invalid")
    owned(IDENTITY_HELPER, executable=True)
    if hashlib.sha256(IDENTITY_HELPER.read_bytes()).hexdigest() != IDENTITY_HELPER_SHA256:
        raise RuntimeError("codex_runtime_identity_mismatch")
    if helper.read_text() != codex_runtime_wrapper(root, interpreter) or cli.read_text() != codex_runtime_wrapper(root, interpreter, "cli"):
        raise RuntimeError("codex_runtime_wrapper_mismatch")
    return CodexRuntime(root, site, interpreter, helper, cli, bootstrap, IDENTITY_HELPER)


def codex_child_environment(runtime: CodexRuntime) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


class InstalledProvider(NamedTuple):
    version: str
    installed: bool
    integrity: str


class RolloutDecision(NamedTuple):
    action: str
    reason: str
    adapter_version: str
    production_eligible: bool
    requires_user_trust: bool
    native_hook_available: bool


_EXACT_NATIVE = {
    "claude_code": {
        "version": "2.1.183",
        "adapter": "1.2.0",
        "production": True,
        "trust": False,
    },
    "gemini_cli": {
        "version": "0.55.1",
        "adapter": "1.0.0",
        "production": False,
        "trust": False,
    },
    "codex": {
        "version": "0.154.0",
        "adapter": "1.0.0",
        "production": False,
        "trust": True,
    },
    "cursor": {
        "version": "3.15.6",
        "adapter": "0.2.0",
        "production": False,
        "trust": False,
    },
}


PRODUCTION_FEATURE_FLAGS = {
    "NATIVE_CONTROL_FRAMEWORK": "true",
    "NATIVE_CONTROL_ADAPTER_FRAMEWORK": "true",
    "NATIVE_CONTROL_REFERENCE_ADAPTERS": "true",
    "NATIVE_CONTROL_ADAPTER_ENFORCEMENT": "true",
    "CONTROL_CAPABILITY_MATRIX": "true",
    "TRUSTED_CONTROL_SELECTOR": "true",
    "NATIVE_CONTROL_MONITOR": "true",
    # Per-provider flags expose the catalog and permit later, individually
    # approved promotion. Global enforcement remains off in this rollout.
    "NATIVE_CONTROL_ENFORCE": "false",
    "NATIVE_CONTROL_ANTHROPIC": "true",
    "NATIVE_CONTROL_GOOGLE": "true",
    "NATIVE_CONTROL_OPENAI": "true",
    "NATIVE_CONTROL_CURSOR": "true",
}


_NATIVE_DETAILS = {
    "claude_code": {
        "provider": "anthropic",
        "product": "claude_code",
        "name": "Claude Code",
        "settings": Path.home() / ".claude/settings.json",
        "events": [
            "session_start", "session_end", "before_tool", "permission_request",
            "after_tool", "after_tool_failure", "config_change", "subagent_start",
            "subagent_stop", "before_agent",
        ],
    },
    "gemini_cli": {
        "provider": "google",
        "product": "gemini_cli",
        "name": "Gemini CLI",
        "settings": Path.home() / ".gemini/settings.json",
        "events": [
            "session_start", "session_end", "before_agent", "after_agent",
            "before_model", "after_model", "before_tool_selection", "before_tool",
            "after_tool", "notification", "pre_compress",
        ],
    },
    "codex": {
        "provider": "openai",
        "product": "codex",
        "name": "Codex",
        "settings": Path.home() / ".codex/hooks.json",
        "events": [
            "session_start", "session_end", "before_tool", "permission_request",
            "after_tool", "pre_compact", "post_compact", "before_agent",
            "subagent_start", "subagent_stop", "stop", "interrupt",
        ],
    },
}


def build_rollout_plan(
    installed: dict[str, InstalledProvider],
) -> dict[str, RolloutDecision]:
    plan: dict[str, RolloutDecision] = {}
    for product, observed in installed.items():
        if product == "chatgpt_desktop":
            plan[product] = RolloutDecision(
                "composite_discovery",
                "native_desktop_hook_unavailable",
                "",
                False,
                False,
                False,
            )
            continue
        accepted = _EXACT_NATIVE.get(product)
        if not observed.installed:
            reason = "not_installed"
        elif observed.integrity != "verified":
            reason = observed.integrity or "integrity_unknown"
        elif accepted is None or observed.version != accepted["version"]:
            reason = "version_not_reviewed"
        else:
            plan[product] = RolloutDecision(
                "install_native_monitor",
                "exact_reviewed_version",
                str(accepted["adapter"]),
                bool(accepted["production"]),
                bool(accepted["trust"]),
                True,
            )
            continue
        plan[product] = RolloutDecision(
            "discovery_only",
            reason,
            str((accepted or {}).get("adapter") or ""),
            False,
            False,
            bool(accepted),
        )
    return plan


def update_env_text(text: str, values: dict[str, str]) -> str:
    lines = text.splitlines()
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key in values:
            positions[key] = index
    for key, value in values.items():
        rendered = f"{key}={value}"
        if key in positions:
            lines[positions[key]] = rendered
        else:
            lines.append(rendered)
    return "\n".join(lines).rstrip() + "\n"


def add_route_bindings(
    existing: str,
    *,
    tenant_id: str,
    integrations: dict[str, str],
) -> str:
    try:
        decoded = json.loads(existing or "{}")
    except json.JSONDecodeError:
        decoded = {}
    if not isinstance(decoded, dict):
        decoded = {}
    tenant = decoded.setdefault(tenant_id, {})
    if not isinstance(tenant, dict):
        tenant = {}
        decoded[tenant_id] = tenant
    configured = tenant.get("runtime_control")
    rows = configured if isinstance(configured, list) else [configured] if isinstance(configured, dict) else []
    providers = {
        "claude_code": ("anthropic", "claude_code", "2.1.183", "1.2.0"),
        "gemini_cli": ("google", "gemini_cli", "0.55.1", "1.0.0"),
        "codex": ("openai", "codex", "0.154.0", "1.0.0"),
    }
    replaced = {providers[key][0] for key in integrations if key in providers}
    output = [row for row in rows if str(row.get("provider") or "") not in replaced]
    for product, integration_id in integrations.items():
        if product not in providers:
            continue
        provider, canonical_product, version, adapter = providers[product]
        output.append(
            {
                "integration_instance_ids": [integration_id],
                "provider": provider,
                "provider_version": version,
                "adapter_version": adapter,
                "product": canonical_product,
            }
        )
    tenant["runtime_control"] = sorted(output, key=lambda row: str(row.get("provider") or ""))
    return json.dumps(decoded, sort_keys=True, separators=(",", ":"))


def write_state(product: str, payload: dict[str, object]) -> Path:
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE_ROOT / f"{product}.rollout.json"
    safe = {
        key: value
        for key, value in payload.items()
        if key in {
            "integration_id", "credential_id", "credential_epoch", "key_tag",
            "provider_version", "adapter_version", "settings_path", "status",
        }
    }
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(safe, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    return path


def validate_identity_helper_signature(helper: Path) -> Path:
    """Bank preflight: exact reviewed helper plus verified developer signature, no key calls."""
    helper = helper.expanduser().absolute()
    try:
        info = helper.lstat()
        if helper.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or not os.access(helper, os.X_OK):
            raise RuntimeError("identity_helper_integrity_invalid")
        if hashlib.sha256(helper.read_bytes()).hexdigest() != IDENTITY_HELPER_SHA256:
            raise RuntimeError("identity_helper_integrity_invalid")
        verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(helper)], capture_output=True, text=True, timeout=5, check=False)
        metadata = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=4", str(helper)], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("identity_helper_unavailable") from exc
    output = f"{metadata.stdout}\n{metadata.stderr}"
    if verified.returncode or metadata.returncode or "Signature=adhoc" in output or re.search(r"^TeamIdentifier=[A-Z0-9]{10}$", output, re.MULTILINE) is None:
        raise RuntimeError("identity_helper_unsigned")
    return helper.resolve()


def local_unsigned_helper_plan() -> dict[str, object]:
    """Non-install preparation only; never reuses or relabels a bank credential."""
    return {
        "status": "local_test_preparation_requires_future_approval",
        "install": False, "activated": False, "requires_explicit_future_approval": True,
        "api": "exact_loopback_only", "key_provider": "macos_secure_enclave",
        "security_profile": "development", "helper_sha256": IDENTITY_HELPER_SHA256,
        "existing_hardware_key_status_public_identity_signature_proof_required": True,
        "distinct_development_integration_credential_config_required": True,
        "approved_registration_operator_required": True,
        "experimental_monitor_only_required": True, "bank_credential_reuse": False,
        "ephemeral_fallback": False, "production_eligible": False, "release_ready": False,
    }


def install_hooks(product: str, enrollment: dict[str, object], *, api_url: str, tenant_id: str, runtime: CodexRuntime | None = None) -> dict[str, object]:
    detail = _NATIVE_DETAILS[product]
    if runtime is not None:
        if product != "codex" or validate_codex_runtime(runtime.root) != runtime:
            raise RuntimeError("codex_runtime_integrity_invalid")
    endpoint_python = runtime.python if runtime else ENDPOINT_PYTHON
    native_helper = runtime.helper if runtime else NATIVE_HELPER
    if not endpoint_python.is_file() or not native_helper.is_file():
        raise RuntimeError("installed Hawk endpoint native-hook runtime is unavailable")
    config = STATE_ROOT / f"{product}.json"
    command = [
        str(endpoint_python), "-m", "hawk_endpoint_agent.native_control.cli", "install",
        "--provider", product,
        "--scope", "user",
        "--settings", str(detail["settings"]),
        "--helper", str(native_helper),
        "--config", str(config),
        "--api-url", api_url,
        "--tenant-id", tenant_id,
        "--integration-id", str(enrollment["integration_id"]),
        "--credential-id", str(enrollment["credential_id"]),
        "--credential-epoch", str(enrollment["credential_epoch"]),
        "--provider-family", str(detail["provider"]),
        "--product", str(detail["product"]),
        "--provider-version", str(enrollment["provider_version"]),
        "--adapter-version", str(enrollment["adapter_version"]),
        "--environment", "production",
        "--key-provider", "macos_secure_enclave",
        "--kms-key-reference", f"secure-enclave://{enrollment['key_tag']}",
        "--security-profile", "bank",
        "--secure-enclave-helper-path", str(runtime.identity if runtime else IDENTITY_HELPER),
    ]
    if runtime is not None:
        command = [str(runtime.cli), *command[3:]]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False, **({"env": codex_child_environment(runtime)} if runtime else {}))
    if result.returncode != 0:
        raise RuntimeError(f"{product} hook installation failed")
    return json.loads(result.stdout)


def _command_version(command: str) -> InstalledProvider:
    path = shutil.which(command)
    if not path:
        return InstalledProvider("", False, "not_installed")
    result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15, check=False)
    match = re.search(r"\b\d+\.\d+\.\d+\b", f"{result.stdout}\n{result.stderr}")
    return InstalledProvider(match.group(0) if match else "unknown", True, "verified" if result.returncode == 0 else "unverified")


def _app_version(path: Path, *, verify_signature: bool) -> InstalledProvider:
    info = path / "Contents/Info.plist"
    if not info.is_file():
        return InstalledProvider("", False, "not_installed")
    with info.open("rb") as stream:
        plist = plistlib.load(stream)
    version = str(plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion") or "unknown")
    integrity = "verified"
    if verify_signature:
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        integrity = "verified" if result.returncode == 0 else "invalid_signature"
    return InstalledProvider(version, True, integrity)


def detect_installed() -> dict[str, InstalledProvider]:
    cursor_paths = [Path.home() / "Applications/Cursor.app", Path("/Applications/Cursor.app")]
    cursor = next((path for path in cursor_paths if path.exists()), cursor_paths[0])
    return {
        "claude_code": _command_version("claude"),
        "gemini_cli": _command_version("gemini"),
        "codex": _command_version("codex"),
        "cursor": _app_version(cursor, verify_signature=True),
        "chatgpt_desktop": _app_version(Path("/Applications/ChatGPT.app"), verify_signature=False),
    }


def _env_value(text: str, key: str, default: str = "") -> str:
    for line in text.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    return default


def apply_feature_flags() -> None:
    original = PRODUCTION_ENV.read_text(encoding="utf-8")
    updated = update_env_text(original, PRODUCTION_FEATURE_FLAGS)
    if updated != original:
        PRODUCTION_ENV.write_text(updated, encoding="utf-8")


def deploy_stack() -> None:
    for operation in ("build", "up"):
        result = subprocess.run(
            [str(PRODUCTION_STACK), operation],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"production stack {operation} failed")


def start_stack() -> None:
    result = subprocess.run(
        [str(PRODUCTION_STACK), "up"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("production stack start failed")


class AdminClient:
    """Short-lived in-memory owner session; never persists bearer material."""

    def __init__(self, base_url: str) -> None:
        endpoint_source = ROOT / "apps/endpoint-agent/src"
        sys.path.insert(0, str(endpoint_source))
        from hawk_endpoint_agent.auth import MemoryTokenVault

        self.base_url = base_url.rstrip("/")
        self.vault = MemoryTokenVault()
        self.tenant_id = ""

    def login(self, email: str, password: str) -> str:
        response = self._raw("POST", "/auth/login", {"email": email, "password": password}, authenticated=False)
        token = str(response.get("access_token") or "")
        self.tenant_id = str(response.get("selected_tenant_id") or "")
        if not token or not self.tenant_id:
            raise RuntimeError("owner login did not return a tenant-scoped session")
        self.vault.store(token, expires_at=time.time() + 25 * 60)
        token = ""
        return self.tenant_id

    def _raw(self, method: str, path: str, body: dict[str, object] | None = None, *, authenticated: bool = True) -> dict[str, object]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if authenticated:
            with self.vault.use() as token_bytes:
                token = token_bytes.decode("utf-8")
                headers["Authorization"] = f"Bearer {token}"
                token = ""
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        context = ssl.create_default_context() if self.base_url.startswith("https://") else None
        try:
            with urllib.request.urlopen(request, timeout=20, context=context) as response:
                decoded = json.loads(response.read().decode("utf-8") or "{}")
                return decoded if isinstance(decoded, dict) else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8")[:1000]
            raise RuntimeError(f"Hawk API rejected {method} {path}: HTTP {exc.code}: {detail}") from exc

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> dict[str, object]:
        return self._raw(method, path, body)

    def close(self) -> None:
        self.vault.close()


def find_existing_integration(
    rows: list[object],
    *,
    provider: str,
    product: str,
    provider_version: str,
    adapter_version: str,
    display_name: str,
) -> dict[str, object] | None:
    """Match only fields returned by the bounded control-point list API."""

    for row in rows:
        if not isinstance(row, dict):
            continue
        if (
            row.get("provider") == provider
            and row.get("product") == product
            and row.get("provider_version") == provider_version
            and row.get("adapter_version") == adapter_version
            and row.get("display_name") == display_name
        ):
            return row
    return None


def _create_integration(client: AdminClient, product: str, installed: InstalledProvider, decision: RolloutDecision) -> dict[str, object]:
    detail = _NATIVE_DETAILS[product]
    instance_key = f"latest-{socket.gethostname().lower()}-{product}-{installed.version}"[:128]
    display_name = f"{detail['name']} {installed.version} — governed monitor"
    listed = client.request("GET", "/control-points")
    existing = find_existing_integration(
        list(listed.get("items") or []),
        provider=str(detail["provider"]),
        product=str(detail["product"]),
        provider_version=installed.version,
        adapter_version=decision.adapter_version,
        display_name=display_name,
    )
    if existing is not None:
        client.request("POST", f"/native-controls/integrations/{existing['id']}/configure")
        return existing
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    return client.request(
        "POST",
        "/native-controls/integrations",
        {
            "provider": detail["provider"],
            "product": detail["product"],
            "model_provider": detail["provider"],
            "model": "unknown",
            "method": "native_hook",
            "instance_key": instance_key,
            "display_name": display_name,
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": installed.version,
            "adapter_version": decision.adapter_version,
            "policy_version": "native-monitor-v1",
            "policy_fresh_until": expires.isoformat(),
            "degradation_mode": "monitor_only",
            "trusted_workload_authority": False,
        },
    )


def _enroll_identity(client: AdminClient, product: str, integration: dict[str, object], installed: InstalledProvider, decision: RolloutDecision, *, runtime: CodexRuntime | None = None) -> dict[str, object]:
    integration_id = str(integration.get("id") or integration.get("integration_id") or "")
    if not integration_id:
        raise RuntimeError("integration response omitted its identifier")
    if runtime is not None and (product != "codex" or validate_codex_runtime(runtime.root) != runtime):
        raise RuntimeError("codex_runtime_integrity_invalid")
    validate_identity_helper_signature(runtime.identity if runtime else IDENTITY_HELPER)
    key_tag = f"com.hawk.endpoint-agent.native-control.{product}.{uuid.uuid4().hex}"
    identity = subprocess.run(
        [str(runtime.identity if runtime else IDENTITY_HELPER), "ensure", key_tag],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if identity.returncode != 0:
        raise RuntimeError(f"{product} Secure Enclave identity creation failed")
    public = json.loads(identity.stdout)
    credential_id = f"{product}-{uuid.uuid4()}"
    epoch = int(time.time())
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    credential = client.request(
        "POST",
        f"/native-controls/integrations/{integration_id}/credentials",
        {
            "credential_id": credential_id,
            "credential_epoch": epoch,
            "public_key_pem": public["public_key_pem"],
            "environment": "production",
            "allowed_event_types": list(_NATIVE_DETAILS[product]["events"]),
            "expires_at": expires.isoformat(),
        },
    )
    return {
        "integration_id": integration_id,
        "credential_id": credential_id,
        "credential_epoch": epoch,
        "key_tag": key_tag,
        "provider_version": installed.version,
        "adapter_version": decision.adapter_version,
        "credential_status": credential.get("status"),
    }


def enroll_native_controls(base_url: str, plan: dict[str, RolloutDecision], installed: dict[str, InstalledProvider]) -> dict[str, dict[str, object]]:
    validate_identity_helper_signature(IDENTITY_HELPER)
    client = AdminClient(base_url)
    try:
        email = input("Hawk owner/admin email: ").strip()
        password = getpass.getpass("Hawk owner/admin password: ")
        tenant_id = client.login(email, password)
        password = ""
        enrolled: dict[str, dict[str, object]] = {}
        for product, decision in plan.items():
            if decision.action != "install_native_monitor":
                continue
            integration = _create_integration(client, product, installed[product], decision)
            enrollment = _enroll_identity(client, product, integration, installed[product], decision)
            install_result = install_hooks(product, enrollment, api_url=base_url, tenant_id=tenant_id)
            enrollment["settings_path"] = install_result.get("settings_path")
            enrollment["status"] = "installed_monitor_pending_live_callback"
            write_state(product, enrollment)
            enrolled[product] = enrollment
        original = PRODUCTION_ENV.read_text(encoding="utf-8")
        routes = add_route_bindings(
            _env_value(original, "NATIVE_CONTROL_ROUTE_BINDINGS_JSON", "{}"),
            tenant_id=tenant_id,
            integrations={product: str(row["integration_id"]) for product, row in enrolled.items()},
        )
        updated = update_env_text(original, {**PRODUCTION_FEATURE_FLAGS, "NATIVE_CONTROL_ROUTE_BINDINGS_JSON": routes})
        PRODUCTION_ENV.write_text(updated, encoding="utf-8")
        return enrolled
    finally:
        client.close()


def codex_backend_accepts_version(client: AdminClient, version: str) -> bool:
    """Require the live tenant API to serve this exact Codex hook schema."""

    item = client.request("GET", "/native-controls/adapters/openai.codex.native-hooks")
    version_range = item.get("provider_version_range")
    return (
        item.get("adapter_id") == "openai.codex.native-hooks"
        and item.get("adapter_version") == _EXACT_NATIVE["codex"]["adapter"]
        and item.get("event_schema_version") == f"codex-hooks/{version}"
        and isinstance(version_range, dict)
        and version_range.get("minimum") == version
        and version_range.get("maximum") == version
    )


def validate_codex_api_base(base_url: str) -> None:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    raise RuntimeError("Codex enrollment requires verified HTTPS or loopback HTTP")


def enroll_codex_only(
    base_url: str,
    installed: InstalledProvider,
    *, runtime_root: Path | None = None,
) -> dict[str, object]:
    """Enroll and install Codex only after the live backend passes exact-version preflight."""

    decision = build_rollout_plan({"codex": installed})["codex"]
    if decision.action != "install_native_monitor":
        raise RuntimeError("installed Codex version is not eligible for native hook enrollment")
    validate_codex_api_base(base_url)
    if runtime_root is None:
        raise RuntimeError("codex_runtime_root_required")
    runtime = validate_codex_runtime(runtime_root)
    validate_identity_helper_signature(runtime.identity)

    client = AdminClient(base_url)
    try:
        email = input("Hawk owner/admin email: ").strip()
        password = getpass.getpass("Hawk owner/admin password: ")
        tenant_id = client.login(email, password)
        password = ""
        if not codex_backend_accepts_version(client, installed.version):
            raise RuntimeError(
                f"live Hawk API does not serve the exact Codex {installed.version} hook schema"
            )

        integrations = enroll_native_controls_after_preflight(client, base_url, tenant_id, installed, decision, **({"runtime": runtime} if runtime else {}))
        return integrations
    finally:
        client.close()


def enroll_native_controls_after_preflight(
    client: AdminClient,
    base_url: str,
    tenant_id: str,
    installed: InstalledProvider,
    decision: RolloutDecision,
    *, runtime: CodexRuntime | None = None,
) -> dict[str, object]:
    """Perform the Codex registration after preflight, without touching stack or env files."""

    validate_identity_helper_signature(runtime.identity if runtime else IDENTITY_HELPER)
    integration = _create_integration(client, "codex", installed, decision)
    enrollment = _enroll_identity(client, "codex", integration, installed, decision, **({"runtime": runtime} if runtime else {}))
    install_result = install_hooks("codex", enrollment, api_url=base_url, tenant_id=tenant_id, **({"runtime": runtime} if runtime else {}))
    enrollment["settings_path"] = install_result.get("settings_path")
    enrollment["status"] = "installed_monitor_pending_live_callback_and_user_trust"
    write_state("codex", enrollment)
    return enrollment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-test-unsigned-helper", action="store_true", help="print a non-install development preparation plan requiring future explicit approval")
    parser.add_argument("--apply", action="store_true", help="enable catalog/monitor flags, enroll exact supported hooks, and rebuild")
    parser.add_argument(
        "--codex-only",
        action="store_true",
        help="enroll the exact supported Codex version using the installed Hawk runtime without stack or env changes",
    )
    parser.add_argument("--codex-runtime-root", type=Path)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if args.local_test_unsigned_helper:
        if args.apply or args.codex_only or args.codex_runtime_root is not None:
            parser.error("local unsigned helper preparation cannot install or enroll")
        print(json.dumps(local_unsigned_helper_plan(), sort_keys=True))
        return 0

    if args.codex_only and args.codex_runtime_root is None:
        parser.error("--codex-only requires --codex-runtime-root")
    if args.codex_runtime_root is not None and not args.codex_only:
        parser.error("--codex-runtime-root requires --codex-only")
    installed = detect_installed()
    plan = build_rollout_plan(installed)
    print(json.dumps({key: {"installed": installed[key]._asdict(), "decision": value._asdict()} for key, value in plan.items()}, sort_keys=True, indent=2))
    if args.codex_only:
        enrollment = enroll_codex_only(args.api_base, installed["codex"], runtime_root=args.codex_runtime_root)
        print(json.dumps({"status": enrollment["status"], "enrolled": ["codex"], "user_trust_required": True}, sort_keys=True))
        return 0
    if not args.apply:
        return 0
    validate_identity_helper_signature(IDENTITY_HELPER)
    apply_feature_flags()
    if not args.skip_build:
        deploy_stack()
    else:
        start_stack()
    enrolled = enroll_native_controls(args.api_base, plan, installed)
    start_stack()
    print(json.dumps({"status": "monitor_paths_installed", "enrolled": sorted(enrolled), "codex_user_trust_required": "codex" in enrolled}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
