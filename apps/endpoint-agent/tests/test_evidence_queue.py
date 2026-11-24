from hawk_endpoint_agent.evidence_queue import EvidenceQueue


def test_acknowledge_removes_only_matching_item(tmp_path) -> None:
    queue = EvidenceQueue(tmp_path / "evidence.json", max_items=10)
    queue.append({"id": "first", "kind": "decision_receipt"})
    queue.append({"id": "second", "kind": "monitor_observation"})

    assert queue.acknowledge("first") is True
    assert [item["id"] for item in queue.items()] == ["second"]
    assert queue.acknowledge("missing") is False
