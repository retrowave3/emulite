from typing import NamedTuple


class StatResult(NamedTuple):
    mode: int  # st_mode (file type | permission bits)
    size: int  # st_size
    rdev: int  # st_rdev (device id, major:minor) — nonzero only for device nodes
    uid: int  # st_uid — per-path: the app owns its own tree, system/root paths are uid 0
    gid: int  # st_gid
    ino: int  # st_ino — stable per path (or per anonymous fd)
