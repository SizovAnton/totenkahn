import os
import sys
from rich.console import Console
from handlers.version import VERSION


def configure_standard_streams():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)

        if not callable(reconfigure):
            continue

        if stream.isatty():
            reconfigure(errors="backslashreplace")
        else:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def create_console():
    configure_standard_streams()

    if "NO_COLOR" in os.environ or (sys.stdout is not None and not sys.stdout.isatty()):
        return Console(legacy_windows=False, force_terminal=False, color_system=None)

    return Console()


def show_startup_banner(arguments, stream=None):
    stream = sys.stderr if stream is None else stream

    if stream is None or not stream.isatty() or sys.stdout is None or not sys.stdout.isatty():
        return

    if "--json" in arguments or "--atomic-plan" in arguments:
        return

    if arguments and arguments[0] == "ci":
        return

    from rich.text import Text

    brand = Text("\n    T  O  T  E  N  K  A  H  N\n", style="bold cyan")
    brand.append(f"             v{VERSION}\n", style="dim")
    Console(
        file=stream,
        legacy_windows=False,
        markup=False,
        highlight=False,
        color_system=None if "NO_COLOR" in os.environ else "auto",
    ).print(brand)
