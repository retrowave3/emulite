from __future__ import annotations

from enum import IntEnum


class SeekWhence(IntEnum):
    SEEK_SET = 0  # start of the file
    SEEK_CUR = 1  # current position
    SEEK_END = 2  # end of the file
