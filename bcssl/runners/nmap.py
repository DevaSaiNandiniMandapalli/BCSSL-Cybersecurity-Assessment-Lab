"""Nmap integration: local host/port/service discovery.

Scope: the loopback host only, and only the ports the instructor has enabled
(3001 by default). The command deliberately avoids everything aggressive:
no OS fingerprinting (``-O``), no aggressive template scanning (``-A``), no UDP
probing, and ``-sT`` (TCP connect) so no elevated privileges are required.

Service and port information is discovery, not vulnerability assessment, so
every finding this runner emits is informational.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from ..executor import CommandSpec, ExecutionResult
from ..parsers import nmap as nmap_parser
from ..parsers.base import ParseResult
from ..runner import BaseRunner
from ..target import TargetValidation

#: Accepted nmap port specifications. Anything else is refused so a
#: misconfigured lab cannot silently widen the scan range.
_PORT_SPEC = re.compile(r"^[0-9,\-]+$")

#: Scan types that stay non-intrusive. SYN (-sS) needs root and is refused.
ALLOWED_SCAN_TYPES = ("-sT",)


class NmapRunner(BaseRunner):
    name: ClassVar[str] = "nmap"
    purpose: ClassVar[str] = "Local host, port and service discovery"
    report_filename: ClassVar[str] = "nmap.xml"
    requires_reachable_target: ClassVar[bool] = False

    def ports(self, options: dict[str, Any]) -> str:
        ports = str(options.get("ports") or self.settings.get("ports") or "3001")
        ports = ports.strip()
        if not _PORT_SPEC.match(ports):
            raise ValueError(
                f"invalid nmap port specification '{ports}'; use digits, "
                "commas and hyphens only (for example 3001 or 1-1024,3001)"
            )
        return ports

    def build_command(
        self,
        validation: TargetValidation,
        options: dict[str, Any],
    ) -> CommandSpec:
        settings = dict(self.settings)
        scan_type = str(options.get("scan_type") or settings.get("scan_type", "-sT"))
        if scan_type not in ALLOWED_SCAN_TYPES:
            raise ValueError(
                f"scan type '{scan_type}' is not permitted by this lab; only "
                f"{', '.join(ALLOWED_SCAN_TYPES)} (TCP connect) is allowed"
            )

        argv: list[str] = [
            str(settings.get("executable") or "nmap"),
            scan_type,
        ]

        service_detection = options.get("service_detection")
        if service_detection is None:
            service_detection = settings.get("service_detection", True)
        if service_detection:
            argv.append("-sV")

        if settings.get("skip_host_discovery", True):
            # -Pn: treat the loopback host as up without an ICMP probe.
            argv.append("-Pn")

        argv.extend(["-p", self.ports(options), "--reason", "-oX", self.report_filename])
        argv.append(validation.host or "localhost")

        return CommandSpec(argv=argv, timeout=self.timeout(options), cwd=str(self.context.run_dir))

    def parse_output(
        self,
        execution: ExecutionResult,
        validation: TargetValidation,
    ) -> ParseResult:
        xml = self.read_report()
        if xml.strip():
            return nmap_parser.parse(xml, target=validation.url)
        # Fall back to the console output when no XML was written.
        result = nmap_parser.parse_text_output(
            execution.stdout, target=validation.url
        )
        if not result.findings:
            result.warnings.append(
                "Nmap did not produce an XML report; console output was parsed "
                "instead and may be incomplete."
            )
        return result
