import os
import sys
import subprocess


# general use
def get_output(*args, **kwargs):
    res = subprocess.check_output(*args, shell=True, **kwargs)
    decoded = res.decode('utf-8')
    return decoded.strip()


# python-gssapi related
def import_gssapi_extension(name):
    """Import a GSSAPI extension module

    This method imports a GSSAPI extension module based
    on the name of the extension (not including the
    'ext_' prefix).  If the extension is not available,
    the method retuns None.

    Args:
        name (str): the name of the extension

    Returns:
        module: Either the extension module or None
    """

    try:
        path = 'gssapi.raw.ext_{0}'.format(name)
        __import__(path)
        return sys.modules[path]
    except ImportError:
        return None


# krb5-plugin related
_PLUGIN_DIR = None


def find_plugin_dir():
    global _PLUGIN_DIR
    if _PLUGIN_DIR is not None:
        return _PLUGIN_DIR

    # if we've set a LD_LIBRARY_PATH, use that first
    ld_path_raw = os.environ.get('LD_LIBRARY_PATH')
    if ld_path_raw is not None:
        # first, try assuming it's just a normal install

        ld_paths = [path for path in ld_path_raw.split(':') if path]

        for ld_path in ld_paths:
            if not os.path.exists(ld_path):
                continue

            _PLUGIN_DIR = _decide_plugin_dir(
                _find_plugin_dirs_installed(ld_path))
            if _PLUGIN_DIR is None:
                _PLUGIN_DIR = _decide_plugin_dir(
                    _find_plugin_dirs_src(ld_path))

            if _PLUGIN_DIR is not None:
                break

    # if there was no LD_LIBRARY_PATH, or the above failed
    if _PLUGIN_DIR is None:
        lib_dir = os.path.join(get_output('krb5-config --prefix'), 'lib64')
        _PLUGIN_DIR = _decide_plugin_dir(_find_plugin_dirs_installed(lib_dir))

    # /usr/lib64 seems only to be distinct on Fedora/RHEL/Centos family
    if _PLUGIN_DIR is None:
        lib_dir = os.path.join(get_output('krb5-config --prefix'), 'lib')
        _PLUGIN_DIR = _decide_plugin_dir(_find_plugin_dirs_installed(lib_dir))

    if _PLUGIN_DIR is not None:
        _PLUGIN_DIR = os.path.normpath(_PLUGIN_DIR)
        return _PLUGIN_DIR
    else:
        return None


def _decide_plugin_dir(dirs):
    if dirs is None:
        return None

    # the shortest path is probably more correct
    shortest_first = sorted(dirs, key=len)

    for path in shortest_first:
        # check to see if it actually contains .so files
        if get_output('find %s -name "*.so"' % path):
            return path

    return None


def _find_plugin_dirs_installed(search_path):
    try:
        options_raw = get_output('find %s/ -type d \( ! -executable -o ! -readable \) '
                                 '-prune -o '
                                 '-type d -path "*/krb5/plugins" -print' % search_path,
                                 stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        options_raw = None

    if options_raw:
        return options_raw.split('\n')
    else:
        return None


def _find_plugin_dirs_src(search_path):
    options_raw = get_output('find %s/../ -type d -name plugins' % search_path)

    if options_raw:
        return options_raw.split('\n')
    else:
        return None
