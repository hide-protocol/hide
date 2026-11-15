"""The rules a binding owes its caller, beyond what the core computes.

Handle lifetime, threads, how the native library is found, and what happens to
text on its way into a C string.
"""

from __future__ import annotations

import copy
import importlib.resources
import os
import pickle
import shutil
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

import hide_protocol as hide
from hide_protocol import _binding

PASSPHRASE = "correct horse battery staple"
# A passphrase that is long enough on its own, followed by a NUL and more: a C
# string read stops at the NUL, so the core would see only the first part.
SPLIT = "longenough\0rest"

SOURCE = str(Path(hide.__file__).resolve().parents[1])
MANIFEST = Path(hide.__file__).resolve().parents[2] / "pyproject.toml"
NO_OVERRIDE = {"HIDE_LIBRARY": None, "HIDE_ALLOW_LIBRARY_OVERRIDE": None}


def _identity() -> hide.SigningIdentity:
    return hide.SigningIdentity.load(
        hide.SigningIdentity.generate(PASSPHRASE), PASSPHRASE
    )


def _child(
    code: str,
    env: dict[str, str | None],
    cwd: str | None = None,
    source: str = SOURCE,
) -> str:
    """Imports the package in a fresh interpreter and returns what it printed.

    The library is chosen once, at import, so only a new process can show how
    a different environment is treated.
    """
    merged = dict(os.environ)
    merged["PYTHONPATH"] = source
    for name, value in env.items():
        if value is None:
            merged.pop(name, None)
        else:
            merged[name] = value
    done = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        env=merged,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


_PROBE = """
    try:
        from hide_protocol import _binding
        print("LOADED", _binding.LIBRARY_PATH)
    except ImportError as error:
        print("IMPORTERROR", error)
"""


def _in_front(directory: Path, name: str) -> str:
    # In front of what is already there: the interpreter itself may need the
    # existing value to start.
    existing = os.environ.get(name)
    return f"{directory}{os.pathsep}{existing}" if existing else str(directory)


def _checkout(root: Path, version: str | None = None) -> Path:
    """Copies the package and its manifest, with the core bundled beside it.

    This is the layout a wheel is built from, and the only way to exercise
    the packaged location: the working tree itself never contains the library.
    """
    package = root / "src" / "hide_protocol"
    shutil.copytree(
        Path(hide.__file__).resolve().parent,
        package,
        ignore=shutil.ignore_patterns("__pycache__", "*.dll", "*.so", "*.dylib"),
    )
    shutil.copy(_binding.LIBRARY_PATH, package / _binding._library_names()[0])
    manifest = MANIFEST.read_text(encoding="utf-8")
    if version is not None:
        manifest = manifest.replace(
            f'version = "{_binding.BINDING_VERSION}"', f'version = "{version}"', 1
        )
        assert f'version = "{version}"' in manifest
    (root / "pyproject.toml").write_text(manifest, encoding="utf-8")
    return package


# --- copies ---------------------------------------------------------------


def _handles() -> list[object]:
    return [hide.SecretKey.generate(), _identity(), hide.SpentNonces()]


@pytest.mark.parametrize("index", [0, 1, 2], ids=["SecretKey", "SigningIdentity", "SpentNonces"])
def test_a_handle_cannot_be_copied_or_pickled(index: int) -> None:
    # A copy would share the native pointer, and whichever of the two was
    # released first would free it under the other.
    handles = _handles()
    handle = handles[index]
    try:
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.copy(handle)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.deepcopy(handle)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.deepcopy({"nested": [handle]})
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with pytest.raises(TypeError, match="cannot be pickled"):
                pickle.dumps(handle, protocol)
    finally:
        for other in handles:
            other.close()  # type: ignore[attr-defined]


def test_the_original_still_works_after_a_refused_copy() -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises(TypeError):
            copy.copy(secret)
        box = hide.encrypt(b"still here", [secret.public_key()])
        assert hide.decrypt(box, secret).data == b"still here"


# --- threads --------------------------------------------------------------


def test_accept_holds_the_record_lock_for_the_native_call() -> None:
    # The native record is mutated without synchronisation and ctypes releases
    # the GIL during the call, so the lock is what makes sharing a record safe.
    # Holding it here must therefore hold back a call made on another thread.
    with _identity() as prover, hide.SpentNonces() as spent:
        public = prover.public_key()
        challenge = hide.new_challenge("ssh://host.example", 1_000, 60)
        answer = prover.answer(challenge)
        finished = threading.Event()

        def accept() -> None:
            spent.accept(challenge, answer, public, 1_000)
            finished.set()

        worker = threading.Thread(target=accept)
        with spent._lock:
            worker.start()
            assert not finished.wait(0.3), "accept ran without taking the lock"
        worker.join(30)
        assert finished.is_set()
        with pytest.raises(hide.ChallengeReplayed):
            spent.accept(challenge, answer, public, 1_000)


def test_one_record_shared_between_threads_accepts_each_answer_once() -> None:
    # Before the lock, a run of this size ended with a few dozen replays
    # accepted: two threads pushing at once lost entries from the record.
    threads, each = 8, 60
    with _identity() as prover, hide.SpentNonces() as spent:
        public = prover.public_key()
        work = []
        for _ in range(threads):
            answers = []
            for _ in range(each):
                challenge = hide.new_challenge("ssh://host.example", 1_000, 60)
                answers.append((challenge, prover.answer(challenge)))
            work.append(answers)

        start = threading.Barrier(threads)
        failures: list[BaseException] = []

        def run(answers: list[tuple[bytes, bytes]]) -> None:
            start.wait()
            for challenge, answer in answers:
                try:
                    spent.accept(challenge, answer, public, 1_000)
                except BaseException as error:  # noqa: BLE001 - reported below
                    failures.append(error)

        workers = [threading.Thread(target=run, args=(answers,)) for answers in work]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(120)
        assert failures == []

        replays_accepted = 0
        for answers in work:
            for challenge, answer in answers:
                try:
                    spent.accept(challenge, answer, public, 1_000)
                    replays_accepted += 1
                except hide.ChallengeReplayed:
                    pass
        assert replays_accepted == 0


def test_a_closed_record_refuses_and_closing_twice_is_harmless() -> None:
    spent = hide.SpentNonces()
    spent.close()
    spent.close()
    with pytest.raises(ValueError):
        spent.accept(b"", b"", b"", 0)


def test_one_key_and_one_identity_serve_several_threads() -> None:
    # The calls only read the native object, so no lock is involved.
    with hide.SecretKey.generate() as secret, _identity() as signer:
        public, verifying = secret.public_key(), signer.public_key()
        box = hide.encrypt(b"shared", [public])
        start = threading.Barrier(6)
        failures: list[BaseException] = []

        def run(index: int) -> None:
            try:
                start.wait()
                for round_ in range(5):
                    message = f"{index}/{round_}".encode()
                    signature = signer.sign(b"example/threads", message)
                    hide.verify(verifying, b"example/threads", message, signature)
                    assert hide.decrypt(box, secret).data == b"shared"
                    assert secret.public_key() == public
            except BaseException as error:  # noqa: BLE001 - reported below
                failures.append(error)

        workers = [threading.Thread(target=run, args=(index,)) for index in range(6)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(120)
        assert failures == []


# --- text that becomes a C string -----------------------------------------


def test_a_passphrase_with_an_embedded_nul_is_refused_not_truncated() -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises(ValueError, match="NUL"):
            secret.protect(SPLIT)
        sealed = secret.protect("longenough")
    # Opening must refuse too: accepting it here would mean the text before
    # the NUL is what unlocks the key.
    with pytest.raises(ValueError, match="NUL"):
        hide.SecretKey.load(sealed, SPLIT)

    with pytest.raises(ValueError, match="NUL"):
        hide.SigningIdentity.generate(SPLIT)
    sealed_identity = hide.SigningIdentity.generate("longenough")
    with pytest.raises(ValueError, match="NUL"):
        hide.SigningIdentity.load(sealed_identity, SPLIT)


def test_every_other_text_argument_refuses_an_embedded_nul() -> None:
    with hide.SecretKey.generate() as secret:
        public = secret.public_key()
        with pytest.raises(ValueError, match="filename"):
            hide.encrypt(b"x", [public], filename="report.txt\0.exe")
        with pytest.raises(ValueError, match="media_type"):
            hide.encrypt(b"x", [public], media_type="text/plain\0x")
        with pytest.raises(ValueError, match="text"):
            hide.dearmor_public_key(hide.armor_public_key(public) + "\0trailing")
    with pytest.raises(ValueError, match="audience"):
        hide.new_challenge("app.example\0.evil.example", 1_000, 60)
    with pytest.raises(ValueError, match="origin"):
        hide.verify_checkpoint(b"note", "log.example\0/hide", b"key")


def test_text_arguments_must_be_text() -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises(TypeError):
            secret.protect(b"a bytes passphrase")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            hide.encrypt(b"x", [secret.public_key()], filename=b"a.txt")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        hide.new_challenge(b"app.example", 1_000, 60)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "filename",
    ["a/b", "a\\b", "..", "CON", "com1.txt", "trailing.", "trailing ", "tab\there",
     "what?.txt", "x" * 256],
)
def test_a_filename_that_is_not_one_portable_file_name_is_refused(filename: str) -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises((hide.HideError, ValueError)):
            hide.encrypt(b"x", [secret.public_key()], filename=filename)


@pytest.mark.parametrize("filename", ["report.txt", "CONSOLE.txt", "x" * 255])
def test_an_ordinary_filename_is_kept(filename: str) -> None:
    with hide.SecretKey.generate() as secret:
        box = hide.encrypt(b"x", [secret.public_key()], filename=filename)
        assert hide.decrypt(box, secret).filename == filename


def test_decrypt_refuses_anything_that_is_not_a_secret_key() -> None:
    with hide.SecretKey.generate() as secret, _identity() as signer:
        box = hide.encrypt(b"x", [secret.public_key()])
        for wrong in ("not a key", None, secret.public_key(), signer):
            with pytest.raises(TypeError, match="SecretKey"):
                hide.decrypt(box, wrong)  # type: ignore[arg-type]


# --- how the native library is found --------------------------------------


def test_the_library_is_loaded_by_absolute_path() -> None:
    assert _binding.LIBRARY_PATH.is_absolute()
    assert _binding.LIBRARY_PATH.is_file()


def test_the_bundled_library_is_found_with_nothing_set(tmp_path: Path) -> None:
    package = _checkout(tmp_path)
    output = _child(_PROBE, NO_OVERRIDE, source=str(tmp_path / "src"))
    assert output.startswith("LOADED "), output
    loaded = Path(output.split(" ", 1)[1])
    assert loaded.name == _binding._library_names()[0]
    assert loaded.parent.samefile(package)


def test_a_core_from_another_release_is_refused_at_import(tmp_path: Path) -> None:
    # The copied binding says 0.0.1; the core beside it is the one under test.
    _checkout(tmp_path, version="0.0.1")
    output = _child(_PROBE, NO_OVERRIDE, source=str(tmp_path / "src"))
    assert output.startswith("IMPORTERROR the HIDE native library is version "), output
    assert "this binding is 0.0.1" in output
    assert "install matching versions" in output


def test_a_library_planted_where_the_system_loader_looks_is_never_loaded(
    tmp_path: Path,
) -> None:
    # A copy of the real core, so that loading it would succeed if anything
    # searched for it by name: in the working directory, on PATH, and on the
    # search paths the Unix loaders honour.
    planted = tmp_path / "hide-planted-core"
    planted.mkdir()
    shutil.copy(_binding.LIBRARY_PATH, planted / _binding._library_names()[0])

    output = _child(
        _PROBE,
        {
            **NO_OVERRIDE,
            "PATH": _in_front(planted, "PATH"),
            "LD_LIBRARY_PATH": _in_front(planted, "LD_LIBRARY_PATH"),
            "DYLD_LIBRARY_PATH": _in_front(planted, "DYLD_LIBRARY_PATH"),
            "DYLD_FALLBACK_LIBRARY_PATH": _in_front(planted, "DYLD_FALLBACK_LIBRARY_PATH"),
        },
        cwd=str(planted),
    )
    assert "hide-planted-core" not in output, output
    # Either the packaged copy loaded, or nothing did.
    if output.startswith("IMPORTERROR"):
        assert "was not found" in output
        assert sys.platform in output
    else:
        assert output.startswith("LOADED")
        assert Path(output.split(" ", 1)[1]).parent == Path(_binding.__file__).resolve().parent


@pytest.mark.parametrize("opt_in", [None, "0", "true", "yes", " 1"])
def test_hide_library_alone_is_ignored(tmp_path: Path, opt_in: str | None) -> None:
    # One settable variable must not be enough to replace the core. The path
    # does not exist, so honouring it could only show up as a load failure
    # that names it.
    absent = tmp_path / "no-such-directory" / "hide_ffi_override"
    output = _child(
        _PROBE, {"HIDE_LIBRARY": str(absent), "HIDE_ALLOW_LIBRARY_OVERRIDE": opt_in}
    )
    assert "no-such-directory" not in output, output
    if output.startswith("IMPORTERROR"):
        assert "was not found" in output


def test_hide_library_with_the_opt_in_is_what_gets_loaded(tmp_path: Path) -> None:
    absent = tmp_path / "no-such-directory" / "hide_ffi_override"
    output = _child(
        _PROBE, {"HIDE_LIBRARY": str(absent), "HIDE_ALLOW_LIBRARY_OVERRIDE": "1"}
    )
    # It is tried, and a failure says so rather than falling back to another copy.
    assert output.startswith("IMPORTERROR"), output
    assert "no-such-directory" in output
    assert "could not be loaded" in output

    real = _child(
        _PROBE,
        {"HIDE_LIBRARY": str(_binding.LIBRARY_PATH), "HIDE_ALLOW_LIBRARY_OVERRIDE": "1"},
    )
    assert real == f"LOADED {_binding.LIBRARY_PATH}"


# --- the core and the binding are the same release ------------------------


def test_the_loaded_core_is_this_bindings_version() -> None:
    assert hide.__version__.split(".")[:3] == _binding.BINDING_VERSION.split(".")[:3]
    _binding.check_version(hide.__version__)


@pytest.mark.parametrize(
    ("core", "binding"),
    [("0.9.1", "0.9.1"), ("1.2.3", "1.2.3"), ("0.10.0-rc.1", "0.10.0"), ("0.10.0", "0.10.0+build.7")],
)
def test_matching_versions_are_accepted(core: str, binding: str) -> None:
    _binding.check_version(core, binding)


@pytest.mark.parametrize(
    ("core", "binding"),
    [
        ("0.9.0", "0.9.1"),   # a stale core beside a newer binding
        ("0.9.2", "0.9.1"),   # and the reverse
        ("0.10.1", "0.9.1"),
        ("1.9.1", "0.9.1"),
        ("0.9.10", "0.9.1"),  # compared as numbers, not as a text prefix
        ("0.91.0", "0.9.10"),
    ],
)
def test_a_core_of_another_version_is_refused(core: str, binding: str) -> None:
    with pytest.raises(ImportError, match="install matching versions"):
        _binding.check_version(core, binding)


@pytest.mark.parametrize("core", ["", "0.9", "v0.9.1", "latest"])
def test_a_core_that_does_not_state_a_version_is_refused(core: str) -> None:
    with pytest.raises(ImportError, match="major.minor.patch"):
        _binding.check_version(core, "0.9.1")


# --- packaging ------------------------------------------------------------


def test_the_package_declares_that_it_ships_type_information() -> None:
    assert importlib.resources.files("hide_protocol").joinpath("py.typed").is_file()
