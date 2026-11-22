from electrum.plugin import hook
from .backup_helper import BackupHelperPlugin, _dbg

_dbg("backup_helper/qt.py loaded")


class Plugin(BackupHelperPlugin):

    @hook
    def daemon_wallet_loaded(self, daemon, wallet):
        _dbg(f"[qt] hook daemon_wallet_loaded, wallet={wallet!r}")
        self._sync_wallet(wallet)

    @hook
    def load_wallet(self, wallet, window=None):
        _dbg(f"[qt] hook load_wallet, wallet={wallet!r}, window={window!r}")
        self._sync_wallet(wallet)

    @hook
    def close_wallet(self, wallet):
        _dbg(f"[qt] hook close_wallet, wallet={wallet!r}")
        self._forget_wallet(wallet)
