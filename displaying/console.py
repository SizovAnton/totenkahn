import sys
from rich.console import Console

def configure_standard_streams():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)

        if not callable(reconfigure):
            continue

        if stream.isatty():
            reconfigure(errors='backslashreplace')
        else:
            reconfigure(encoding='utf-8', errors='backslashreplace')

def create_console():
    configure_standard_streams()

    if sys.stdout is not None and (not sys.stdout.isatty()):
        return Console(legacy_windows=False, force_terminal=False, color_system=None)

    return Console()

def show_startup_banner(arguments, stream=None):
    stream = sys.stderr if stream is None else stream

    if stream is None or not stream.isatty():
        return

    if '--json' in arguments or '--atomic-plan' in arguments:
        return

    if arguments and arguments[0] == 'ci':
        return

    print('[ totenkahn ]  detection validation', file=stream)
