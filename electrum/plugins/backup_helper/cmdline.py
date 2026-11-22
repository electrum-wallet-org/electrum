from electrum.plugin import hook
from .backup_helper import BackupHelperPlugin, _dbg

_dbg("backup_helper/cmdline.py loaded")


class Plugin(BackupHelperPlugin):

    @hook
    def daemon_wallet_loaded(self, daemon, wallet):
        _dbg(f"[cmdline] hook daemon_wallet_loaded, wallet={wallet!r}")
        self._sync_wallet(wallet)

    @hook
    def load_wallet(self, wallet, window=None):
        _dbg(f"[cmdline] hook load_wallet, wallet={wallet!r}")
        self._sync_wallet(wallet)

    @hook
    def close_wallet(self, wallet):
        _dbg(f"[cmdline] hook close_wallet, wallet={wallet!r}")
        self._forget_wallet(wallet)
