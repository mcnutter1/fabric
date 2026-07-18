"""Fabric DNS resolver — intercepts endpoint DNS, applies category/domain
filtering from policy, forwards allowed queries upstream, and logs everything.

Runs a small UDP DNS server (dnslib). Blocked domains return NXDOMAIN (or a
sinkhole address) and a `block` DNS event; allowed domains are resolved upstream
and logged as `resolve`. Degrades to a no-op if dnslib is unavailable or the
socket cannot be bound (e.g. unprivileged dev runs).
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Optional

from .classify import Classifier
from .policy import FlowCtx, PolicyBundle

log = logging.getLogger("fabric.agent.dns")


class DNSResolver:
    def __init__(self, bind: str, upstream: str, classifier: Classifier,
                 on_event: Callable[[dict], None]):
        self.bind_host, _, port = bind.partition(":")
        self.port = int(port or 53)
        self.upstream = upstream
        self.classifier = classifier
        self.on_event = on_event
        self._bundle: Optional[PolicyBundle] = None
        self._server = None
        self._thread: Optional[threading.Thread] = None

    def set_policy(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    def start(self) -> bool:
        try:
            from dnslib.server import DNSServer, BaseResolver
            from dnslib import RR, QTYPE, A, RCODE
        except Exception as e:  # noqa: BLE001
            log.info("DNS filtering disabled (dnslib unavailable: %s)", e)
            return False

        outer = self

        class _Resolver(BaseResolver):
            def resolve(self, request, handler):
                reply = request.reply()
                qname = str(request.q.qname).rstrip(".")
                client_ip = handler.client_address[0] if handler.client_address else ""
                category = outer.classifier.classify_domain(qname)
                action = outer._decide(qname, category)
                if action == "block":
                    reply.header.rcode = RCODE.NXDOMAIN
                    outer._log(qname, client_ip, category, "block", "")
                    return reply
                answer_ip = outer._forward(qname, str(QTYPE[request.q.qtype]))
                if answer_ip:
                    try:
                        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(answer_ip), ttl=60))
                    except Exception:
                        pass
                outer._log(qname, client_ip, category, "resolve", answer_ip or "")
                return reply

        try:
            self._server = DNSServer(_Resolver(), port=self.port, address=self.bind_host)
            self._server.start_thread()
            log.info("DNS resolver listening on %s:%d (upstream %s)",
                     self.bind_host, self.port, self.upstream)
            return True
        except Exception as e:  # noqa: BLE001
            log.info("DNS resolver could not bind %s:%d (%s)", self.bind_host, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.stop()
            except Exception:
                pass

    # ------------------------------------------------------------ internals
    def _decide(self, qname: str, category: str) -> str:
        if not self._bundle:
            return "resolve"
        v = self._bundle.evaluate(FlowCtx(domain=qname, category=category, node_roles=["ingress"]))
        if v.action in ("deny", "block_page", "sinkhole"):
            return "block"
        return "resolve"

    def _forward(self, qname: str, qtype: str) -> str:
        """Forward the query upstream and return the first A answer (best effort)."""
        try:
            from dnslib import DNSRecord
            q = DNSRecord.question(qname, qtype if qtype in ("A", "AAAA") else "A")
            packet = q.send(self.upstream, 53, timeout=3)
            ans = DNSRecord.parse(packet)
            for rr in ans.rr:
                if rr.rtype in (1,):  # A
                    return str(rr.rdata)
        except Exception:
            pass
        return ""

    def _log(self, qname: str, client_ip: str, category: str, action: str, answer: str) -> None:
        self.on_event({
            "qname": qname, "qtype": "A", "answer": answer,
            "category": category, "action": action, "client_ip": client_ip,
        })
