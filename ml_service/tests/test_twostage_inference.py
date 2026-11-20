"""
Unit tests for NetShield Phase 19.6 Two-Stage & Uncertainty Detection Policies.
Verifies Stage 1 binary detection, Stage 2 multi-class routing, and suspicious traffic flagging.
"""

import pytest
import numpy as np

def simulate_twostage_decision(class_probs, class_names, benign_idx=0, tau_attack=0.40, tau_certainty=0.75):
    """
    Two-stage decision policy simulator.
    """
    p_benign = class_probs[benign_idx]
    p_attack = 1.0 - p_benign
    
    attack_indices = [i for i in range(len(class_names)) if i != benign_idx]
    
    if p_attack >= tau_attack:
        # Stage 2: pick the attack class with highest probability
        best_attack = max(attack_indices, key=lambda idx: class_probs[idx])
        return {
            "prediction": class_names[best_attack],
            "is_attack": True,
            "is_suspicious": False,
            "confidence": float(class_probs[best_attack])
        }
    elif p_benign < tau_certainty:
        # Uncertainty zone: mark as Suspicious / Unknown
        best_attack = max(attack_indices, key=lambda idx: class_probs[idx])
        return {
            "prediction": "Suspicious / Unknown",
            "is_attack": True, # Flagged for review
            "is_suspicious": True,
            "confidence": float(p_attack)
        }
    else:
        return {
            "prediction": class_names[benign_idx],
            "is_attack": False,
            "is_suspicious": False,
            "confidence": float(p_benign)
        }

def test_twostage_high_attack_probability():
    classes = ["BENIGN", "DDoS", "PortScan", "Bot"]
    # P(BENIGN) = 0.35, P(DDoS) = 0.50 -> Attack probability = 0.65 >= 0.40
    probs = [0.35, 0.50, 0.10, 0.05]
    res = simulate_twostage_decision(probs, classes, benign_idx=0, tau_attack=0.40)
    assert res["is_attack"] is True
    assert res["prediction"] == "DDoS"
    assert res["is_suspicious"] is False

def test_twostage_distributed_attack_probabilities():
    classes = ["BENIGN", "DoS Hulk", "PortScan", "Web Attack"]
    # P(BENIGN) = 0.55 -> Argmax would predict BENIGN!
    # But P(Attack) = 0.45 >= 0.40 -> Two-stage catches this as Attack!
    probs = [0.55, 0.25, 0.15, 0.05]
    res = simulate_twostage_decision(probs, classes, benign_idx=0, tau_attack=0.40)
    assert res["is_attack"] is True
    assert res["prediction"] == "DoS Hulk"
    assert res["is_suspicious"] is False

def test_twostage_uncertainty_zone():
    classes = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    # P(Normal) = 0.65 -> Between 0.50 and tau_certainty (0.75)
    # P(Attack) = 0.35 (< tau_attack 0.45)
    probs = [0.65, 0.15, 0.10, 0.08, 0.02]
    res = simulate_twostage_decision(probs, classes, benign_idx=0, tau_attack=0.45, tau_certainty=0.75)
    assert res["is_attack"] is True
    assert res["is_suspicious"] is True
    assert res["prediction"] == "Suspicious / Unknown"

def test_twostage_high_confidence_benign():
    classes = ["BENIGN", "DDoS", "PortScan"]
    # P(BENIGN) = 0.98 -> Confident Benign
    probs = [0.98, 0.01, 0.01]
    res = simulate_twostage_decision(probs, classes, benign_idx=0, tau_attack=0.40, tau_certainty=0.75)
    assert res["is_attack"] is False
    assert res["is_suspicious"] is False
    assert res["prediction"] == "BENIGN"
