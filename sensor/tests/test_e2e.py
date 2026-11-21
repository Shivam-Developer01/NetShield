import os
from sensor.src.config.settings import SensorSettings
from sensor.src.main import NetworkSensorApp

def test_sensor_full_pcap_pipeline_nsl_kdd():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_test.pcap")
    if not os.path.exists(sample_path):
        pytest.skip("sample_test.pcap not found")

    settings = SensorSettings(
        sensor_mode="pcap",
        pcap_file=sample_path,
        dataset_type="nsl_kdd",
        backend_url="http://localhost:5000",
        ml_service_url="http://localhost:8000"
    )

    app = NetworkSensorApp(settings)
    app.ml_client.authenticate_sensor()
    app.run_pcap(sample_path)

    assert app.stats["packets_captured"] == 10
    assert app.stats["flows_generated"] == 3
    assert app.stats["flows_processed"] == 3
    assert app.stats["flows_rejected"] == 0
    assert app.stats["predictions_sent"] == 3
    assert app.stats["errors"] == 0

def test_sensor_full_pcap_pipeline_cicids2017():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_test.pcap")
    if not os.path.exists(sample_path):
        pytest.skip("sample_test.pcap not found")

    settings = SensorSettings(
        sensor_mode="pcap",
        pcap_file=sample_path,
        dataset_type="cicids2017",
        backend_url="http://localhost:5000",
        ml_service_url="http://localhost:8000"
    )

    app = NetworkSensorApp(settings)
    app.ml_client.authenticate_sensor()
    app.run_pcap(sample_path)

    assert app.stats["packets_captured"] == 10
    assert app.stats["flows_generated"] == 3
    assert app.stats["flows_processed"] == 3
    assert app.stats["flows_rejected"] == 0
    assert app.stats["predictions_sent"] == 3
    assert app.stats["errors"] == 0
