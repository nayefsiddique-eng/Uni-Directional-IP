"""
Feature Emitter Handoff Interface (FR4).
Streams JSON line records or writes batch files for downstream ML Module (Person 2) consumption.
"""

import json
import logging
import sys
from typing import List, Optional, TextIO
from ..schema.flow_schema import FlowRecord

logger = logging.getLogger("TrafficPipeline.FeatureEmitter")

class FeatureEmitter:
    def __init__(self, output_filepath: Optional[str] = None, stream_to_stdout: bool = False):
        self.output_filepath = output_filepath
        self.stream_to_stdout = stream_to_stdout
        self.emitted_count = 0
        self._file_handle: Optional[TextIO] = None

        if self.output_filepath:
            self._file_handle = open(self.output_filepath, mode='a', encoding='utf-8')

    def emit_flow(self, flow: FlowRecord) -> str:
        """Emits single flow record as serialized JSON string."""
        json_str = flow.to_json()
        
        if self._file_handle:
            self._file_handle.write(json_str + "\n")
            self._file_handle.flush()

        if self.stream_to_stdout:
            sys.stdout.write(json_str + "\n")
            sys.stdout.flush()

        self.emitted_count += 1
        return json_str

    def emit_batch(self, flows: List[FlowRecord]) -> int:
        """Emits a batch list of flow records."""
        for f in flows:
            self.emit_flow(f)
        return len(flows)

    def close(self):
        if self._file_handle and not self._file_handle.closed:
            self._file_handle.close()
            self._file_handle = None
