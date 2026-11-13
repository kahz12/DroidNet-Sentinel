"""
Core Scanner Module — network discovery, port scanning and ARP response.

Flow per cycle:
    get_wifi_info → ping_sweep → identify_devices → deep_scan
                 → add_dhcp_fingerprints → evaluate_risk → save_report
                 → display_table → cut_unknowns → send_alert

A passive DHCP listener (core.dhcp) runs alongside for the whole session.
"""

import json
import ipaddress
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.config       import (
    CHECK_INTERVAL,
    RESCAN_HOURS,
    REPORTS_DIR,
    load_user_config,
)
from droidnet.core.database  import init_db, save_scan, purge_old_scans, record_guard_event
from droidnet.core.devices   import is_locally_administered, mdns_probe, reverse_lookup
from droidnet.core.dhcp      import DhcpListener, os_hint
from droidnet.core.guard     import terminating_signals
from droidnet.core.logger    import get_logger
from droidnet.core.markup    import esc
from droidnet.core.risk      import classify_risk, is_scan_error
from droidnet.core.notifier  import send_alert, escape_html
from droidnet.core.upnp      import cast_probe, ssdp_probe
from droidnet.platform.utils import (
    get_default_iface,
    get_default_gateway,
    get_wifi_info,
    wake_lock,
)

log = get_logger(__name__)

console = Console()


# ══════════════════════════════════════════════════════════════════
#  Risk evaluation
# ══════════════════════════════════════════════════════════════════
# Single source of truth for the port→risk mapping lives in core.risk
# (classify_risk). Here we only decorate it with Rich markup for the TUI.

_RISK_MARKUP = {
    "UNKNOWN":  "[bold yellow]UNKNOWN[/bold yellow]",
    "MINIMAL":  "[bold green]MINIMAL[/bold green]",
    "LOW":      "[bold blue]LOW[/bold blue]",   # blue — matches README + dashboard
    "MEDIUM":   "[bold yellow]MEDIUM[/bold yellow]",
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
}


def evaluate_risk(ports: list[str]) -> str:
    """Return the Rich-markup version of classify_risk(ports)."""
    label = classify_risk(ports)
    return _RISK_MARKUP.get(label, esc(label))


# ══════════════════════════════════════════════════════════════════
#  Display
# ══════════════════════════════════════════════════════════════════

def _device_cell(meta: dict) -> str:
    """Device column: the model the device reported, else nmap's OUI vendor,
    else a note for a randomized MAC; then, on a second line, the operating
    system its DHCP requests revealed, when known.

    The vendor beats the note when nmap knows the prefix: a few locally
    administered prefixes are real (QEMU's 52:54:00). A randomized MAC is
    the default on modern phones, so the note is informational and never
    affects risk. The DHCP line is what still describes such a phone:
    "Randomized MAC" over "Android 14".
    """
    label = meta.get("model") or meta.get("vendor")
    if label:
        cell = esc(label)
    elif is_locally_administered(meta.get("mac")):
        cell = "[italic]Randomized MAC[/italic]"
    else:
        cell = ""
    system = meta.get("os")
    if system and (not label or system.lower() not in label.lower()):
        cell = f"{cell}\n{esc(system)}" if cell else esc(system)
    return cell or "—"


def display_results_table(
    ssid: str,
    scan_data: dict,
    metadata: dict[str, dict] | None = None,
) -> None:
    """
    Render a Rich table with scan results.

    Args:
        ssid      : Network name shown in the title.
        scan_data : {ip: [port_entries]} from deep_scan.
        metadata  : Optional {ip: {hostname, mac, vendor, model}} from
                    ping_sweep and identify_devices, to enrich the table.
    """
    metadata = metadata or {}

    table = Table(
        title        = f"[bold cyan]Sentinel audit: {esc(ssid)}[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta",
    )
    table.add_column("Target (IP)",       style="dim",   width=15)
    table.add_column("Hostname",          style="white", width=18, overflow="fold")
    table.add_column("Device",            style="dim",   width=18, overflow="fold")
    table.add_column("Risk",              justify="center")
    table.add_column("Ports/Versions",    style="green")
    table.add_column("Services",          style="yellow")

    for ip, results in scan_data.items():
        meta     = metadata.get(ip, {})
        # Hostname (DHCP / mDNS), model, vendor and banners are set by the
        # devices themselves; table cells are parsed as markup, so escape them.
        ip_cell  = esc(ip)
        hostname = esc(meta.get("hostname") or "—")
        device   = _device_cell(meta)
        risk     = evaluate_risk(results)

        if results == ["Shield intact"]:
            table.add_row(
                ip_cell, hostname, device, risk,
                "[blue]Closed[/blue]", "Protected device",
            )
        elif results and is_scan_error(results[0]):
            table.add_row(
                ip_cell, hostname, device, "[white]???[/white]",
                "[red]Failed[/red]", "Scan error",
            )
        else:
            ports    = "\n".join(p.split()[0]           for p in results)
            services = "\n".join(" ".join(p.split()[2:]) for p in results)
            table.add_row(ip_cell, hostname, device, risk, esc(ports), esc(services))

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Discovery
# ══════════════════════════════════════════════════════════════════

def _parse_nmap_sn(output: str) -> dict[str, dict]:
    """Parse completed discovery XML; malformed/incomplete results raise."""
    root = ET.fromstring(output)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Incomplete Nmap discovery")
    hosts: dict[str, dict] = {}
    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address[@addrtype='ipv4']")
        if status is None or status.get("state") != "up" or address is None:
            continue
        ip = str(ipaddress.IPv4Address(address.get("addr")))
        name = host.find("hostnames/hostname")
        mac = host.find("address[@addrtype='mac']")
        hosts[ip] = {"hostname": name.get("name") if name is not None else None,
                     "mac": mac.get("addr") if mac is not None else None,
                     "vendor": mac.get("vendor") if mac is not None else None}
    return hosts


def _run_nmap_sn(args: list[str]) -> tuple[int, str]:
    """Run an nmap discovery command. Returns (returncode, stdout)."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=180,
            stdin=subprocess.DEVNULL,
        )
        if proc.returncode != 0:
            log.warning("nmap discovery failed exit=%d stderr=%s",
                        proc.returncode, (proc.stderr or "").strip())
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        rprint("[yellow][-] ping_sweep timed out (180 s). Slow or very crowded network.[/yellow]")
        log.warning("nmap discovery timed out (180s)")
        return 124, ""
    except Exception as exc:
        log.warning("nmap discovery failed: %s", exc)
        return 1, ""


def ping_sweep(ip_address: str, excluded: list[str]) -> dict[str, dict] | None:
    """
    Host discovery on the /24 subnet of *ip_address*.

    Primary:  nmap -sn (default probes — ICMP+ARP under root, TCP otherwise).
    Fallback: nmap -PE -PA80 -PS22,80,443 -sn  (more explicit probes
              when the network filters ICMP or ARP isn't visible without root).

    Args:
        ip_address : Local IP of this device (e.g. 192.168.1.100).
        excluded   : IPs to skip (at minimum: our own IP).

    Returns:
        {ip: {"hostname": ..., "mac": ..., "vendor": ...}}
    """
    subnet      = ".".join(ip_address.split(".")[:-1]) + ".0/24"
    exclude_arg = ["--exclude", ",".join(excluded)] if excluded else []

    completed_empty = False
    for probes in ([], ["-PE", "-PA80", "-PS22,80,443"]):
        rc, out = _run_nmap_sn(["nmap", "-sn", "-oX", "-", *probes, subnet] + exclude_arg)
        if rc != 0:
            continue
        try:
            hosts = _parse_nmap_sn(out)
        except (ET.ParseError, ValueError, TypeError):
            continue
        if hosts:
            return hosts
        completed_empty = True
    # An empty successful primary remains valid even if the optional fallback
    # is unavailable. None means neither command completed a usable scan.
    return {} if completed_empty else None


def _probe_result(future, source: str) -> dict:
    """A probe's result, or {} if it was skipped or failed: names and models
    are extras, so a failing probe never costs the scan."""
    if future is None:
        return {}
    try:
        return future.result() or {}
    except Exception:
        log.exception("device identification failed source=%s", source)
        return {}


def identify_devices(metadata: dict[str, dict], my_ip: str) -> None:
    """Add names and models to *metadata* in place, from what devices say.

    Four sources run in parallel, each with a deadline of a few seconds:
      - the router's reverse DNS, which on most home routers returns the
        name each device sent over DHCP (nmap asks the system resolver,
        which on Termux is a public server that knows no LAN names);
      - mDNS asked of each host: its .local name, a model, the name its
        owner gave it;
      - UPnP descriptions found with one SSDP search: maker and model;
      - the description Google Cast devices serve on port 8008, for the
        Chromecasts and Google TVs that answer neither mDNS nor SSDP.

    A hostname nmap found is kept; otherwise the router's, then the mDNS
    host name, then the owner's name for the device (mDNS, then UPnP, then
    Cast). The model is taken in that same source order. None of it needs
    root, and a source that fails or is not there adds nothing.
    """
    ips = list(metadata)
    if not ips:
        return
    missing = [ip for ip in ips if not metadata[ip].get("hostname")]
    gateway = get_default_gateway(my_ip) if missing else None
    with ThreadPoolExecutor(max_workers=4) as pool:
        router = pool.submit(reverse_lookup, missing, gateway) if gateway else None
        mdns   = pool.submit(mdns_probe, ips)
        ssdp   = pool.submit(ssdp_probe, my_ip, ips)
        cast   = pool.submit(cast_probe, ips)
        router_names = _probe_result(router, "router-dns")
        mdns_hints   = _probe_result(mdns, "mdns")
        upnp_hints   = _probe_result(ssdp, "ssdp")
        cast_hints   = _probe_result(cast, "cast")

    for ip, meta in metadata.items():
        # Most specific first: mDNS names the exact model ("Google Nest
        # Mini"); a UPnP or Cast description often names only the product line.
        sources = (mdns_hints.get(ip, {}), upnp_hints.get(ip, {}), cast_hints.get(ip, {}))
        meta["model"] = next((s["model"] for s in sources if s.get("model")), None)
        if not meta.get("hostname"):
            meta["hostname"] = (router_names.get(ip) or sources[0].get("hostname")
                                or next((s["name"] for s in sources if s.get("name")), None))
    log.info("device identification hosts=%d router_names=%d mdns=%d upnp=%d cast=%d",
             len(ips), len(router_names), len(mdns_hints), len(upnp_hints), len(cast_hints))


def add_dhcp_fingerprints(metadata: dict[str, dict], listener: DhcpListener | None) -> None:
    """Add what passive DHCP listening learnt about each host, in place.

    meta["os"] gets the operating-system hint from the host's latest DHCP
    request (see core.dhcp.os_hint), and the hostname it announced (option
    12) fills the Hostname column when no other source named the host.
    """
    if listener is None or not listener.running:
        return
    matched = 0
    for ip, meta in metadata.items():
        request = listener.lookup(meta.get("mac"), ip)
        if request is None:
            continue
        matched += 1
        # Only record an OS when the fingerprint actually yields one. Writing
        # meta["os"] = None for an unknown hint leaves a key present-but-None,
        # which a consumer that tests `"os" in meta` would misread as "known".
        os_guess = os_hint(request)
        if os_guess:
            meta["os"] = os_guess
        if not meta.get("hostname") and request.hostname:
            meta["hostname"] = request.hostname
    log.info("dhcp fingerprints clients=%d matched=%d", len(listener.clients()), matched)


_DEEP_SCAN_WORKERS = 16

# Each host is scanned in two nmap passes with separate budgets. Port
# discovery over the top 100 TCP ports takes a second or two on a LAN host.
# Version detection is the slow part: services that never answer nmap's
# probes make every probe wait out its timeout — a home router's two HTTP
# ports took 124 s — so it gets a much larger budget of its own.
_PORT_SCAN_TIMEOUT    = 120
_VERSION_SCAN_TIMEOUT = 300

# Port states that mean "nothing answers here": closed ports reply with a
# reset, filtered ones are dropped by a firewall. Either way the port exposes
# no service to this network.
_UNEXPOSED_STATES = {"closed", "filtered"}


def _nmap_host(ip: str, nmap_args: list[str], timeout: int):
    """Run nmap against *ip* with XML output.

    Returns the <host> element, or an "Error: ..." marker string when nmap
    fails, the run is incomplete or the host is down. Timeouts and malformed
    XML propagate to the caller, which knows what a failure costs.
    """
    proc = subprocess.run(
        ["nmap", *nmap_args, "-oX", "-", ip],
        capture_output=True, text=True, timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        log.warning("nmap failed ip=%s exit=%d stderr=%s", ip, proc.returncode, proc.stderr.strip())
        return "Error: nmap failed"
    root = ET.fromstring(proc.stdout)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        return "Error: incomplete scan"
    host = root.find("host")
    if host is None or host.find("status") is None or host.find("status").get("state") != "up":
        return "Error: host unreachable"
    return host


def _parse_ports(host) -> tuple[dict[str, str], list[str | None]]:
    """Open ports as {"80/tcp": "80/tcp open http nginx 1.18.0"} plus every state seen.

    The port id is parsed as an int so only digits ever reach a later
    ``nmap -p`` argument.
    """
    open_ports: dict[str, str] = {}
    states = [extra.get("state") for extra in host.findall("ports/extraports")]
    for port in host.findall("ports/port"):
        state = port.find("state")
        state_name = state.get("state") if state is not None else None
        states.append(state_name)
        if state_name != "open":
            continue
        key = f"{int(port.get('portid'))}/{port.get('protocol')}"
        service = port.find("service")
        attrs = service.attrib if service is not None else {}
        banner = " ".join(attrs.get(k, "") for k in ("product", "version")).strip()
        if attrs.get("extrainfo"):
            banner += f" ({attrs['extrainfo']})"
        open_ports[key] = f"{key} open {attrs.get('name', 'unknown')} {banner}".strip()
    return open_ports, states


def _with_versions(ip: str, open_ports: dict[str, str]) -> list[str]:
    """Add product/version strings to *open_ports* with ``nmap -sV`` on just those ports.

    The open ports alone already decide the host's risk, so any failure here
    (timeout, nmap error, bad XML) keeps the first-pass lines and only loses
    the version strings. A port that stopped answering between the two passes
    also keeps its first-pass line.
    """
    port_list = ",".join(key.split("/")[0] for key in open_ports)
    try:
        host = _nmap_host(ip, ["-sV", "-T4", "-p", port_list], _VERSION_SCAN_TIMEOUT)
        if isinstance(host, str):
            raise RuntimeError(host)
        versioned, _ = _parse_ports(host)
    except Exception as exc:
        log.warning("version detection failed ip=%s (%s); keeping the port list",
                    ip, type(exc).__name__ if isinstance(exc, subprocess.TimeoutExpired) else exc)
        return list(open_ports.values())
    return [versioned.get(key, line) for key, line in open_ports.items()]


def _scan_one(ip: str) -> tuple[str, list[str]]:
    """Scan one host: ports first (-F -T4), then versions on the open ones (-sV).

    Returns (ip, lines) where lines are open-port lines, ["Shield intact"]
    when nothing is exposed, or a single "Error: ..." marker when the port
    scan itself could not tell.
    """
    try:
        host = _nmap_host(ip, ["-F", "-T4"], _PORT_SCAN_TIMEOUT)
        if isinstance(host, str):
            return ip, [host]
        open_ports, states = _parse_ports(host)
        if open_ports:
            return ip, _with_versions(ip, open_ports)
        if states and all(state in _UNEXPOSED_STATES for state in states):
            return ip, ["Shield intact"]
        # No port data at all, or states nmap could not settle (open|filtered).
        return ip, ["Error: inconclusive port states"]
    except subprocess.TimeoutExpired:
        return ip, ["Error: timeout"]
    except Exception as exc:
        log.warning("host scan failed ip=%s: %s", ip, exc)
        return ip, ["Error"]


def _scan_into(pool: ThreadPoolExecutor, ips: list[str], results: dict) -> None:
    """Scan *ips* on *pool*, storing each host's lines in *results* as it finishes."""
    for fut in as_completed([pool.submit(_scan_one, ip) for ip in ips]):
        ip, lines = fut.result()
        results[ip] = lines


def deep_scan(live_ips: list[str]) -> dict:
    """
    Port and version scan on each live IP, in parallel.

    Per host (see _scan_one): -F -T4 over the top 100 TCP ports, then -sV
    on the ports found open. Up to 16 hosts in parallel (I/O-bound: the GIL
    is released while nmap runs). Hosts that come back with an error marker
    ("Error" or "Error: ...") are scanned once more after all the others
    have finished.

    Returns:
        {ip: [open port lines]}, {ip: ["Shield intact"]} for closed hosts,
        or {ip: [error marker]} for hosts that failed both attempts.
    """
    if not live_ips:
        return {}

    workers = min(_DEEP_SCAN_WORKERS, len(live_ips))
    results: dict = {}
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        _scan_into(pool, live_ips, results)

        # Phones and tablets with Wi-Fi power saving can answer discovery and
        # then doze off before their port scan, so nmap reports them down and
        # they would stay UNKNOWN for the whole cycle. Every host left with an
        # error marker (down, timeout, inconclusive states) gets one more scan
        # once all first attempts are done; a second failure is kept as the
        # result, so a host that is really gone costs one extra attempt only.
        retry = [ip for ip, lines in results.items() if lines and is_scan_error(lines[0])]
        if retry:
            log.info("rescanning hosts that could not be assessed: %s", ", ".join(retry))
            rprint(f"[dim][*] Rescanning {len(retry)} host(s) that could not be assessed...[/dim]")
            _scan_into(pool, retry, results)
    finally:
        # On Ctrl+C do not start queued scans. Running nmap passes keep their
        # own timeouts (_PORT_SCAN_TIMEOUT / _VERSION_SCAN_TIMEOUT); wait for
        # them before reporting shutdown.
        pool.shutdown(wait=True, cancel_futures=True)
    return results


# ══════════════════════════════════════════════════════════════════
#  Active response
# ══════════════════════════════════════════════════════════════════

class _CutEvent(threading.Event):
    """Stop event for an ARP-cut worker thread.

    poison() calls stop_event.wait(interval) once it has verified its backend
    (arpspoof or Scapy), resolved the victim/gateway MACs and sent the first
    forged frames. Deferring the 'cut' journal entry until that first wait()
    ensures an early abort (missing tool, unreachable MAC, bad interface) is
    never recorded as an active cut or a subsequent restore.
    """

    def __init__(self, on_active) -> None:
        super().__init__()
        self.active = False
        self.ready = threading.Event()
        self._on_active = on_active

    def wait(self, timeout=None) -> bool:
        if not self.active and not self.is_set():
            self.active = True
            self._on_active()
            self.ready.set()
        return super().wait(timeout)


class AutoCutSession:
    """Own response jobs; reconcile targets and restore them before returning.

    Every job started and stopped is written to the guard journal (set
    `network` so the record names the Wi-Fi it happened on), so there is an
    audit trail of who was cut and when, independent of whether the process
    exits cleanly.
    """

    # Marker for "not currently refusing", distinct from any SSID (None
    # included). Used to dedupe the auto-cut refusal so a daemon left with an
    # empty allowlist does not append an identical "refused" row every cycle.
    _UNSET = object()

    def __init__(self):
        self.jobs: dict[tuple[str, str, str], tuple[_CutEvent, threading.Thread]] = {}
        self.network: str | None = None
        self._refused_network = AutoCutSession._UNSET

    def update(self, targets: set[tuple[str, str, str]]) -> None:
        for key in list(self.jobs):
            stop, thread = self.jobs[key]
            alive = thread.is_alive()
            if key not in targets or not alive:
                stop.set()
                thread.join()
                del self.jobs[key]
                # Only a live thread that actually started poisoning sends
                # corrective ARP on its way out (poison() restores in its
                # finally). A thread that already died on its own or never
                # started poisoning never restored its victim, so journalling a
                # "restore" for it would be a false entry in the security trail.
                if alive and stop.active:
                    record_guard_event("restore", ip=key[0], network=self.network)
        for key in targets - self.jobs.keys():
            stop = _CutEvent(
                lambda ip=key[0], net=self.network: record_guard_event(
                    "cut", ip=ip, network=net, reason="not in trusted_ips"
                )
            )
            thread = threading.Thread(target=self._run, args=(key, stop))
            self.jobs[key] = stop, thread
            try:
                thread.start()
            except BaseException:
                del self.jobs[key]
                raise
            stop.ready.wait(timeout=0.5)
            if not thread.is_alive() and not stop.active:
                thread.join()
                del self.jobs[key]

    @staticmethod
    def _run(key, stop):
        from droidnet.modules.spoofer import poison
        try:
            poison(*key, stop_event=stop)
        except Exception:
            log.exception("ARP response failed for %s", key[0])
        finally:
            stop.ready.set()

    def wait(self):
        while any(thread.is_alive() for _, thread in self.jobs.values()):
            time.sleep(0.2)

    def close(self):
        # Only threads still alive that actually started poisoning will send
        # corrective ARP when stopped; ones that already died or aborted early
        # never restored their victim, so they must not be journalled as
        # restored (same reasoning as update()).
        alive_jobs = [(key[0], stop) for key, (stop, thread) in self.jobs.items() if thread.is_alive()]
        for stop, _ in self.jobs.values():
            stop.set()
        for _, thread in self.jobs.values():
            thread.join()
        self.jobs.clear()
        for ip, stop in alive_jobs:
            if stop.active:
                record_guard_event("restore", ip=ip, network=self.network)


def cut_unknowns(targets: list[str], my_ip: str, config: dict,
                 jobs: AutoCutSession | None = None, network: str | None = None) -> None:
    """
    Launch ARP spoofing threads against every IP not in trusted_ips.

    The local host and the default gateway are always protected, even when
    absent from trusted_ips — cutting them would ARP-poison the operator and
    knock every device on the LAN off the internet. The gateway is detected
    from the routing table (not hard-assumed to be .1).
    Jobs are owned by the scan session and stopped when it exits.

    The target set is re-derived from the current scan on every call, never
    replayed from a saved list, so a device that changed IP is still matched
    by "not in trusted_ips" and a trusted device that took an old IP is not
    cut by mistake.

    An empty trusted_ips means "nothing is trusted", which under auto-cut
    would knock every real device off the network — almost always a
    misconfiguration rather than an intent. In that case the cut is refused
    (logged to the guard journal) and the scanner keeps monitoring, so the
    operator notices without the network going down. The guardian becomes
    active as soon as trusted_ips is set, which the loop re-reads each cycle.

    Args:
        targets : Active IPs found by ping_sweep.
        my_ip   : Local IP of this device.
        config  : Loaded user config dict (needs "trusted_ips" key).
        network : SSID, recorded with each cut in the guard journal.
    """
    if jobs is None:
        owned = AutoCutSession()
        try:
            cut_unknowns(targets, my_ip, config, owned, network)
            owned.wait()
        finally:
            owned.close()
        return

    jobs.network = network

    if not config.get("trusted_ips"):
        if jobs.jobs:
            jobs.update(set())
        rprint("[yellow][-] auto-cut needs a non-empty trusted_ips allowlist; "
               "refusing to cut every device. Monitoring only.[/yellow]")
        log.warning("auto-cut refused: trusted_ips is empty (network=%s)", network)
        # Record the refusal once per refusing streak (and again when the SSID
        # changes), not on every scan cycle of a long-running guardian.
        if jobs._refused_network != network:
            record_guard_event("refused", network=network, reason="trusted_ips empty")
            jobs._refused_network = network
        return

    # Trust is configured again: clear the refusal state so that a later
    # removal of trusted_ips is journalled afresh instead of deduped away.
    jobs._refused_network = AutoCutSession._UNSET

    gateway = get_default_gateway(my_ip)
    if not gateway:
        jobs.update(set())
        rprint("[yellow][-] Could not determine the gateway. Skipping ARP cut.[/yellow]")
        return

    # Always protect the local host and gateway, independent of trusted_ips.
    protected = [ipaddress.ip_network(value, strict=False)
                 for value in [*config.get("trusted_ips", []), my_ip, gateway]]
    unknown = [ip for ip in targets
               if not any(ipaddress.ip_address(ip) in network for network in protected)]

    if not unknown:
        jobs.update(set())
        rprint("[dim][-] No unknown hosts. Network is clean.[/dim]")
        return

    iface = get_default_iface()
    jobs.update({(ip, gateway, iface) for ip in unknown})


# ══════════════════════════════════════════════════════════════════
#  Persistence
# ══════════════════════════════════════════════════════════════════

def _sanitize_ssid(ssid: str) -> str:
    """Strip everything except word chars and hyphens to prevent path traversal."""
    return re.sub(r'[^\w\-]', '_', ssid) or "unknown"


def save_report(ssid: str, scan_data: dict) -> Path:
    """
    Save *scan_data* to reports/<SSID>_<timestamp>.json.

    Returns:
        Path to the created file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = _sanitize_ssid(ssid)
    filename  = REPORTS_DIR / f"{safe_ssid}_{ts}.json"

    # Final guard: ensure resolved path is inside REPORTS_DIR.
    if filename.resolve().parent != REPORTS_DIR.resolve():
        raise ValueError(f"Report path escapes REPORTS_DIR: {filename}")

    with filename.open("w") as fh:
        json.dump({"network": ssid, "time": ts, "targets": scan_data}, fh, indent=4)

    return filename


# ══════════════════════════════════════════════════════════════════
#  Main scan loop
# ══════════════════════════════════════════════════════════════════

def _build_sentinel_report(ssid: str, live_count: int) -> str:
    """Telegram (HTML mode) summary of one scan. The SSID is attacker-controlled."""
    return (
        "🛡️ <b>DroidNet Sentinel Report</b>\n\n"
        f"📡 <b>Network:</b> <code>{escape_html(ssid)}</code>\n"
        f"🎯 <b>Live targets:</b> {live_count}\n"
        "⚠️ <b>Check the Command Center for details.</b>"
    )


def run_sentinel(interactive: bool = True, auto_cut: bool = False) -> None:
    """Run scans and ensure all automatic responses stop on exit.

    The passive DHCP listener runs for the whole session: devices only show
    up in it when they join or rejoin the network, so the hours of a daemon
    session are what make it useful. It needs root and stays off otherwise.

    Shutdown is handled for Ctrl+C and for SIGTERM/SIGHUP alike (see
    core.guard), so a guardian stopped by `systemctl stop` or by closing its
    terminal still restores every ARP table on the way out. A Termux wake
    lock keeps a daemon from being frozen by Doze between scans.
    """
    jobs = AutoCutSession()
    dhcp = DhcpListener()
    dhcp.start()
    if auto_cut:
        # Create the schema before the first journal write: on a brand-new
        # database the guard_events table must exist, or this guard_start row
        # is silently dropped and the trail ends up with an orphan guard_stop.
        init_db()
        record_guard_event("guard_start", reason="interactive" if interactive else "daemon")
    try:
        with terminating_signals(), wake_lock():
            _run_sentinel_loop(interactive, auto_cut, jobs, dhcp)
    finally:
        dhcp.stop()
        jobs.close()
        if auto_cut:
            record_guard_event("guard_stop")


def _run_sentinel_loop(interactive: bool, auto_cut: bool, jobs: AutoCutSession,
                       dhcp: DhcpListener | None = None) -> None:
    """
    Main Sentinel loop.

    Modes:
        interactive=True  → single scan cycle, then return.
        interactive=False → daemon: loops every CHECK_INTERVAL seconds,
                            re-scans when the SSID changes or RESCAN_HOURS pass.

    Args:
        interactive : True for one-shot scan, False for daemon mode.
        auto_cut    : If True, executes cut_unknowns automatically on
                      hosts not listed in trusted_ips. Default is False
                      (opt-in) — ARP cutting is destructive.
    """
    # Ensure the schema exists before any scan writes (idempotent). Done here
    # rather than at import so merely importing the module never touches the DB.
    init_db()

    last_ssid       = None
    last_scan_time  = datetime.min
    last_purge_time = datetime.min  # daily DB retention sweep

    rprint("[bold yellow][!][/bold yellow] DroidNet Sentinel ready.")

    while True:
        info   = get_wifi_info()
        config = load_user_config()
        if not info or info.get("ssid") != last_ssid or not info.get("ip"):
            jobs.update(set())
        elif jobs.jobs:
            # Revoke jobs when trust settings change, even between scans.
            cut_unknowns([key[0] for key in jobs.jobs], info["ip"], config, jobs,
                         network=info.get("ssid"))

        # ── Daily DB retention sweep ─────────────────────────────
        # Opt-out by setting db_retention_days <= 0 in config.json.
        retention_days = int(config.get("db_retention_days", 90))
        now_for_purge  = datetime.now()
        if retention_days > 0 and (now_for_purge - last_purge_time) > timedelta(days=1):
            try:
                deleted = purge_old_scans(retention_days)
                if deleted:
                    log.info("db purge deleted=%d retention_days=%d",
                             deleted, retention_days)
            except Exception as exc:
                log.warning("db purge failed: %s", exc)
            last_purge_time = now_for_purge

        if info:
            current_ssid = info.get("ssid", "Unknown network")
            my_ip        = info.get("ip")
            now          = datetime.now()

            should_scan = (
                interactive
                or current_ssid != last_ssid
                or (now - last_scan_time) > timedelta(hours=RESCAN_HOURS)
            )

            if should_scan and my_ip and my_ip != "0.0.0.0":
                rprint(f"\n[bold green][*][/bold green] Scanning network: [bold white]{esc(current_ssid)}[/bold white]")
                log.info("scan started network=%s my_ip=%s auto_cut=%s",
                         current_ssid, my_ip, auto_cut)

                excluded = list(config.get("excluded_ips", []))
                if my_ip not in excluded:
                    excluded.append(my_ip)

                metadata = ping_sweep(my_ip, excluded)
                if metadata is None:
                    log.warning("discovery failed network=%s; retry next cycle", current_ssid)
                    jobs.update(set())
                    if interactive:
                        break
                    time.sleep(CHECK_INTERVAL)
                    continue
                identify_devices(metadata, my_ip)
                live_ips = list(metadata.keys())
                results = deep_scan(live_ips)
                # After the port scan, so requests heard while it ran count too.
                add_dhcp_fingerprints(metadata, dhcp)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_report(current_ssid, results)
                save_scan(current_ssid, ts, results)
                display_results_table(current_ssid, results, metadata)
                log.info("scan finished network=%s hosts=%d", current_ssid, len(live_ips))
                if auto_cut:
                    cut_unknowns(live_ips, my_ip, config, jobs, network=current_ssid)
                if not live_ips:
                    rprint("[yellow][-] No hosts detected on the network.[/yellow]")
                    log.warning("scan empty network=%s (no hosts detected)",
                                current_ssid)

                send_alert(
                    title       = "Sentinel Alert",
                    local_msg   = f"{len(live_ips)} hosts analysed on {current_ssid}",
                    telegram_msg= _build_sentinel_report(current_ssid, len(live_ips)),
                )

                last_ssid, last_scan_time = current_ssid, now

        if interactive:
            if auto_cut:
                rprint("[dim]Press Ctrl+C to stop active responses and restore ARP.[/dim]")
                jobs.wait()
            break

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    import sys
    run_sentinel(
        interactive="--daemon" not in sys.argv,
        auto_cut="--auto-cut" in sys.argv,
    )
