"""Short-lived result cache kept in memory only.

Keys are SHA-256 hashes of the submitted text, so the cache never holds the
message itself as a key. Entries expire after a few minutes and disappear on
restart; nothing here is written to disk.
"""

import hashlib
import threading
import time
from collections import OrderedDict

from app import config


class ResultCache:
    def __init__(self, ttl_seconds: int, max_entries: int):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._data: OrderedDict[str, tuple[float, bytes]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(text: str, patterns_version: str) -> str:
        # Including the pattern version means a pattern update never serves stale results.
        return hashlib.sha256(f"{patterns_version}\x00{text}".encode("utf-8")).hexdigest()

    def get(self, key: str) -> bytes | None:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None or item[0] < now:
                if item is not None:
                    del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return item[1]

    def set(self, key: str, value: bytes) -> None:
        if self.ttl <= 0 or self.max_entries <= 0:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + self.ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


results = ResultCache(config.CACHE_TTL_SECONDS, config.CACHE_MAX_ENTRIES)
