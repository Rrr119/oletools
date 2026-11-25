"""Compatibility alias for :mod:`oletools.vba_deobfuscator`."""

from oletools import vba_deobfuscator as _implementation

for _name in dir(_implementation):
    if not _name.startswith('_'):
        globals()[_name] = getattr(_implementation, _name)
