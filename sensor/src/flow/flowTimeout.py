import time
from typing import Dict, List
from sensor.src.models.flow import FlowKey, Flow

class FlowTimeoutTracker:
    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds

    def is_expired(self, flow: Flow, current_time: float) -> bool:
        return (current_time - flow.last_time) >= self.timeout_seconds

    def check_expired_flows(self, active_flows: Dict[FlowKey, Flow], current_time: float) -> List[Flow]:
        expired = []
        for key, flow in list(active_flows.items()):
            if self.is_expired(flow, current_time):
                expired.append(flow)
        return expired
