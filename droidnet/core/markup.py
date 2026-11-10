"""Safe interpolation of external text into Rich markup."""

from rich.markup import escape


def esc(value) -> str:
    """Escape untrusted text for Rich markup.

    Banners, hostnames, vendors and SSIDs come from devices on the scanned
    network; NVD / Exploit-DB fields and saved reports are external data.
    Interpolated raw into markup, a stray "[/x]" raises MarkupError and
    aborts the run, and a "[link=...]" injects a terminal hyperlink.
    Accepts any value (None, numbers) and renders its str() literally.
    """
    return escape(str(value))
