#!/usr/bin/env python3
"""
Bifrost eBPF Collector v0.1.0

Loads the eBPF syscall monitor into the kernel,
reads events from the ring buffer, and feeds them
into Guardian's event queue.

This is the fastest collector - microsecond latency
from syscall to event in queue.
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime, timezone
from queue import Full, Queue

from bifrost.collector_logging import log_collector_error

log = logging.getLogger("heimdall.bpf_collector")

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    log.warning("BCC not available. eBPF collector disabled.")
    BCC_AVAILABLE = False


class BPFCollector(threading.Thread):
    """
    Loads eBPF program and streams syscall events
    to the Guardian event queue.
    """
    
    BPF_PROGRAM = "kernel/ebpf/syscall_monitor.bpf.c"
    
    def __init__(self, queue: Queue, shutdown_event: threading.Event, log):
        super().__init__(daemon=True, name="collector.ebpf")
        self.queue = queue
        self.shutdown = shutdown_event
        self.log = log
        self.bpf = None
        self._log_rate_limits = {}
        
    def load_program(self):
        """Load the eBPF program into the kernel."""
        if not BCC_AVAILABLE:
            self.log.error("BCC not available. Cannot load eBPF program.")
            return False
            
        if not os.path.exists(self.BPF_PROGRAM):
            self.log.error(f"eBPF program not found: {self.BPF_PROGRAM}")
            return False
            
        try:
            self.log.info("Loading eBPF program...")
            self.bpf = BPF(src_file=self.BPF_PROGRAM)
            self.log.info("✅ eBPF program loaded into kernel")
            return True
        except (OSError, RuntimeError, ValueError) as e:
            log_collector_error(
                self.log,
                self._log_rate_limits,
                "load_program",
                logging.ERROR,
                f"Failed to load eBPF program {self.BPF_PROGRAM}",
                e,
            )
            return False
    
    def handle_event(self, cpu, data, size):
        """Callback for each eBPF event from ring buffer."""
        try:
            # Parse the event structure from C
            event = self.bpf["events"].event(data)
            
            # Convert to Guardian event format
            guardian_event = {
                "source": "ebpf",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "boundary": "HOST",
                "raw": {
                    "pid": event.pid,
                    "uid": event.uid,
                    "comm": event.comm.decode('utf-8', errors='ignore'),
                    "type": event.type.decode('utf-8', errors='ignore'),
                    "path": event.path.decode('utf-8', errors='ignore'),
                    "ip": self._format_ip(event.ip) if event.ip else None,
                    "port": event.port if event.port else None
                }
            }
            
            # Send to Guardian's event queue
            try:
                self.queue.put_nowait(guardian_event)
            except Full as e:
                log_collector_error(
                    self.log,
                    self._log_rate_limits,
                    "queue_full",
                    logging.WARNING,
                    f"Dropping eBPF event pid={event.pid}",
                    e,
                )
                
        except (AttributeError, KeyError, TypeError, ValueError,
                UnicodeDecodeError) as e:
            # Event decoding can fail on missing ring-buffer fields, malformed
            # bytes, or unexpected callback payloads from the BPF map wrapper.
            log_collector_error(
                self.log,
                self._log_rate_limits,
                "handle_event",
                logging.WARNING,
                "Event parsing error in BPFCollector.handle_event",
                e,
            )
    
    def _format_ip(self, ip: int) -> str:
        """Convert IP from integer to string."""
        return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"
    
    def run(self):
        """Main thread loop - reads events from eBPF ring buffer."""
        self.log.info("BPFCollector starting...")
        
        if not self.load_program():
            self.log.error("BPF program load failed. Collector disabled.")
            return
        
        # Open ring buffer and register callback
        self.bpf["events"].open_ring_buffer(self.handle_event)
        
        self.log.info("✅ eBPF collector active - monitoring kernel syscalls")
        
        # Poll ring buffer for events
        while not self.shutdown.is_set():
            try:
                self.bpf.ring_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except (OSError, RuntimeError, ValueError) as e:
                log_collector_error(
                    self.log,
                    self._log_rate_limits,
                    "ring_buffer_poll",
                    logging.ERROR,
                    "Ring buffer poll error",
                    e,
                )
                time.sleep(1)
        
        self.log.info("BPFCollector shutting down...")
