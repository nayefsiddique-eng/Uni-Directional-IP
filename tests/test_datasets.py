import os
import csv
import pytest
from src.datasets.dataset_loader import DatasetLoader

def test_cicids_dataset_loader(tmp_path):
    csv_file = str(tmp_path / "mock_cicids.csv")
    headers = [
        "Source IP", "Destination IP", "Source Port", "Destination Port",
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
        "Flow Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Label"
    ]
    
    rows = [
        ["192.168.1.10", "10.0.0.1", "54321", "80", "6", "1000000", "5", "5", "500", "1500", "2000.0", "10.0", "60", "300", "200.0", "50.0", "BENIGN"],
        ["192.168.1.15", "10.0.0.5", "54322", "80", "6", "500000", "100", "2", "10000", "100", "20200.0", "204.0", "60", "1000", "500.0", "100.0", "DDoS"],
        ["192.168.1.20", "10.0.0.8", "54323", "443", "6", "2000000", "10", "10", "2000", "2000", "2000.0", "10.0", "100", "200", "150.0", "20.0", "Bot"]
    ]

    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    loader = DatasetLoader()
    records = loader.load_cicids_csv(csv_file)

    assert len(records) == 3
    assert records[0].label == "benign"
    assert records[1].label == "ddos"
    assert records[2].label == "c2_beaconing"
    assert records[1].fwd_packets == 100
