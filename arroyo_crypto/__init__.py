
# Please refrain from specifying a micro version if possible.
# --------------------------------------------------------------------------- #
VERSION = (1, 0, 'b2')
# --------------------------------------------------------------------------- #


def _get_version(vt):                                                           # pragma: nocover # noqa
    vt = tuple(map(str, vt))                                                    # pragma: nocover # noqa
    m = map(lambda v: v.startswith(('a', 'b', 'rc')), vt)                       # pragma: nocover # noqa
    try:                                                                        # pragma: nocover # noqa
        i = next(i for i, v in enumerate(m) if v)                               # pragma: nocover # noqa
    except StopIteration:                                                       # pragma: nocover # noqa
        return '.'.join(vt)                                                     # pragma: nocover # noqa
    return '.'.join(vt[:i]) + '.'.join(vt[i:])                                  # pragma: nocover # noqa


__version__ = _get_version(VERSION)

del _get_version
