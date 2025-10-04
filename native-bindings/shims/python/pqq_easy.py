"""Thin ctypes wrapper for the Velocity (pqq-native) easy C API.

The wrapper exposes high-level helpers that accept/return Python dictionaries
while delegating to the JSON-configurable C bindings.

Example:

    from pqq_easy import EasyClient, EasyServer

    server = EasyServer({
        "bind": "127.0.0.1:0",
        "profile": "balanced",
        "static_text": "Hello Velocity!",
    })

    client = EasyClient({
        "server_addr": server.address,
        "hostname": "localhost",
        "server_key_base64": server.kem_public_base64,
    })

    print(client.get("/"))
    server.close()
"""
from __future__ import annotations

import json
import os
import sys
import ctypes
from ctypes import (
    c_char_p,
    c_int32,
    c_size_t,
    c_uint16,
    c_void_p,
    POINTER,
    Structure,
)
from typing import Any, Dict, Optional

__all__ = [
    "PqqOwnedSlice",
    "load_library",
    "easy_start_server",
    "easy_request",
    "EasyServer",
    "EasyClient",
]


class PqqOwnedSlice(Structure):
    _fields_ = [
        ("data", c_void_p),
        ("len", c_size_t),
        ("release", c_void_p),
        ("release_ctx", c_void_p),
    ]


def _default_library_paths() -> list[str]:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "target"))
    release = os.path.join(root, "release")
    debug = os.path.join(root, "debug")
    names = []
    env = os.getenv("PQQ_NATIVE_LIB")
    if env:
        names.append(env)
    if sys.platform == "win32":
        names.extend(
            [
                os.path.join(release, "pqq_native.dll"),
                os.path.join(debug, "pqq_native.dll"),
            ]
        )
    elif sys.platform == "darwin":
        names.extend(
            [
                os.path.join(release, "libpqq_native.dylib"),
                os.path.join(debug, "libpqq_native.dylib"),
            ]
        )
    else:
        names.extend(
            [
                os.path.join(release, "libpqq_native.so"),
                os.path.join(debug, "libpqq_native.so"),
            ]
        )
    return names


def load_library(path: Optional[str] = None) -> ctypes.CDLL:
    candidates = [path] if path else []
    candidates.extend(_default_library_paths())
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            lib = ctypes.CDLL(candidate)
            _configure_signatures(lib)
            lib.pqq_init()
            return lib
    raise FileNotFoundError("Unable to locate pqq_native shared library")


def _configure_signatures(lib: ctypes.CDLL) -> None:
    lib.pqq_init.argtypes = []
    lib.pqq_init.restype = None

    lib.pqq_easy_start_server.argtypes = [c_char_p, POINTER(PqqOwnedSlice)]
    lib.pqq_easy_start_server.restype = c_int32

    lib.pqq_easy_request.argtypes = [c_char_p, POINTER(PqqOwnedSlice)]
    lib.pqq_easy_request.restype = c_int32

    lib.pqq_owned_slice_release.argtypes = [POINTER(PqqOwnedSlice)]
    lib.pqq_owned_slice_release.restype = None

    lib.pqq_stop_server.argtypes = [c_uint16]
    lib.pqq_stop_server.restype = c_int32


def _slice_to_str(lib: ctypes.CDLL, slice_: PqqOwnedSlice) -> str:
    if slice_.len == 0 or not slice_.data:
        return ""
    buf = ctypes.string_at(slice_.data, slice_.len)
    lib.pqq_owned_slice_release(ctypes.byref(slice_))
    return buf.decode("utf-8")


def easy_start_server(lib: ctypes.CDLL, config: Dict[str, Any]) -> Dict[str, Any]:
    payload = json.dumps(config).encode("utf-8")
    slice_ = PqqOwnedSlice()
    rc = lib.pqq_easy_start_server(payload, ctypes.byref(slice_))
    if rc != 0:
        raise RuntimeError(f"pqq_easy_start_server failed with code {rc}")
    return json.loads(_slice_to_str(lib, slice_))


def easy_request(lib: ctypes.CDLL, config: Dict[str, Any]) -> Dict[str, Any]:
    payload = json.dumps(config).encode("utf-8")
    slice_ = PqqOwnedSlice()
    rc = lib.pqq_easy_request(payload, ctypes.byref(slice_))
    if rc != 0:
        raise RuntimeError(f"pqq_easy_request failed with code {rc}")
    return json.loads(_slice_to_str(lib, slice_))


class EasyServer:
    def __init__(self, config: Dict[str, Any], lib: Optional[ctypes.CDLL] = None) -> None:
        self.lib = lib or load_library()
        self._info = easy_start_server(self.lib, config)

    @property
    def info(self) -> Dict[str, Any]:
        return self._info

    @property
    def port(self) -> int:
        return int(self._info["port"])

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def kem_public_base64(self) -> str:
        return str(self._info["kem_public_base64"])

    def close(self) -> None:
        self.lib.pqq_stop_server(c_uint16(self.port))


class EasyClient:
    def __init__(self, base_config: Dict[str, Any], lib: Optional[ctypes.CDLL] = None) -> None:
        self.lib = lib or load_library()
        self.base_config = dict(base_config)

    def get(self, path: str = "/") -> Dict[str, Any]:
        cfg = dict(self.base_config)
        cfg.setdefault("path", path)
        return easy_request(self.lib, cfg)

__all__ = [name for name in __all__]  # appease linters
