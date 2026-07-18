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
import time
from typing import Callable, Optional

from .classify import Classifier
from .policy import FlowCtx, PolicyBundle

log = logging.getLogger("fabric.agent.dns")


class DNSResolver:
    def __init__(self, bind: str, upstream: str, classifier: Classifier,
                 on_event: Callable[[dict], None], sinkhole: str = ""):
        self.bind_host, _, port = bind.partition(":")
        self.port = int(port or 53)
        self.upstream = upstream
        self.classifier = classifier
        self.on_event = on_event
        self.sinkhole = sinkhole or ""
        self._bundle: Optional[PolicyBundle] = None
        self._server = None
        self._thread: Optional[threading.Thread] = None

    def set_policy(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    def start(self) -> bool:
        try:
            from dnslib.server import DNSServer, BaseResolver
            from dnslib import RR, QTYPE, A, AAAA, RCODE
        except Exception as e:  # noqa: BLE001
            log.info("DNS filtering disabled (dnslib unavailable: %s)", e)
            return False

        outer = self

        class _Resolver(BaseResolver):
            def resolve(self, request, handler):
                qname = str(request.q.qname).rstrip(".")
                qtype = QTYPE.get(request.q.qtype, str(request.q.qtype))
                client_ip = handler.client_address[0] if handler.client_address else ""
                category = outer.classifier.classify_domain(qname)
                action, sink = outer._decide(qname, category)
                if action == "block":
                    reply = request.reply()
                    answer = ""
                    if sink:
                        # Override: steer the client to our own sinkhole / block
                        # page address instead of the real host.
                        try:
                            if qtype == "AAAA" and ":" in sink:
                                reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(sink), ttl=30))
                                answer = sink
                            elif qtype in ("A", "ANY", "HTTPS") and ":" not in sink:
                                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(sink), ttl=30))
                                answer = sink
                            else:
                                # Query type we can't satisfy with this sink -> NODATA.
                                answer = ""
                        except Exception:  # noqa: BLE001
                            reply.header.rcode = RCODE.NXDOMAIN
                    else:
                        reply.header.rcode = RCODE.NXDOMAIN
                    outer._log(qname, client_ip, qtype, category, "block", answer, 0.0)
                    return reply
                # Allowed: relay the FULL upstream response (A/AAAA/CNAME/MX/TXT/...)
                # so clients get complete, working answers — not just one A record.
                reply, answer, ms = outer._forward_full(request)
                outer._log(qname, client_ip, qtype, category, "resolve", answer, ms)
                return reply

        try:
            self._server = DNSServer(_Resolver(), port=self.port, address=self.bind_host)
            self._server.start_thread()
            log.info("DNS resolver listening on %s:%d (upstream %s, sinkhole %s)",
                     self.bind_host, self.port, self.upstream, self.sinkhole or "-")
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
    def _decide(self, qname: str, category: str) -> tuple:
        """Return (action, override_ip). action is 'resolve' or 'block';
        override_ip is a sinkhole/block-page address to answer with, or '' for
        an NXDOMAIN (hard block)."""
        if not self._bundle:
            return ("resolve", "")
        v = self._bundle.evaluate(FlowCtx(domain=qname, category=category, node_roles=["ingress"]))
        if v.action in ("deny", "block", "block_page", "sinkhole"):
            params = v.params or {}
            sink = params.get("sinkhole") or params.get("ip") or params.get("redirect_ip") or ""
            # block_page / sinkhole imply steering to an address; a plain deny is
            # NXDOMAIN unless the rule explicitly supplies one.
            if not sink and v.action in ("block_page", "sinkhole"):
                sink = self.sinkhole
            return ("block", sink)
        return ("resolve", "")

    def _forward_full(self, request) -> tuple:
        """Forward the raw query upstream and relay the complete response.

        Returns (reply_record, first_addr_answer, latency_ms). Retries over TCP
        when the UDP answer is truncated so large answer sets aren't lost.
        """
        from dnslib import DNSRecord, RCODE
        host, _, port = self.upstream.partition(":")
        up_port = int(port or 53)
        t0 = time.monotonic()
        try:
            pkt = request.send(host, up_port, tcp=False, timeout=4)
            resp = DNSRecord.parse(pkt)
            if resp.header.tc:  # truncated -> re-ask over TCP for the full set
                pkt = request.send(host, up_port, tcp=True, timeout=4)
                resp = DNSRecord.parse(pkt)
            ms = (time.monotonic() - t0) * 1000.0
            answer = ""
            for rr in resp.rr:
                if rr.rtype in (1, 28):  # A / AAAA
                    answer = str(rr.rdata)
                    break
            if not answer and resp.rr:
                answer = str(resp.rr[0].rdata)
            return resp, answer, ms
        except Exception:  # noqa: BLE001
            r = request.reply()
            r.header.rcode = RCODE.SERVFAIL
            return r, "", (time.monotonic() - t0) * 1000.0

    def _log(self, qname: str, client_ip: str, qtype: str, category: str,
             action: str, answer: str, latency_ms: float = 0.0) -> None:
        self.on_event({
            "qname": qname, "qtype": qtype, "answer": answer,
            "category": category, "action": action, "client_ip": client_ip,
            "latency_ms": round(latency_ms, 1),
        })
