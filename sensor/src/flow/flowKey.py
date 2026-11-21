from sensor.src.models.flow import FlowKey

def extract_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
    """
    Utility wrapper returning (FlowKey, is_forward)
    """
    return FlowKey.create(src_ip, dst_ip, src_port, dst_port, protocol)
