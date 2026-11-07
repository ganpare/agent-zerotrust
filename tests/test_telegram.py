"""Tests for the Telegram adapter: formatting and chunking."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence.telegram import MAX_LEN, format_briefing, split_message  # noqa: E402

SAMPLE = {
    "request_id": "session-review-abc123",
    "policy_tier": "ask",
    "evidence": [
        {"event_id": "e1", "source": "warpgate",
         "action": "ssh session via warpgate as ai-muse"},
        {"event_id": "e2", "source": "tetragon",
         "action": "read /home/ai-muse/canary-secret.txt"},
        {"event_id": "e3", "source": "tetragon",
         "action": "connect 93.184.216.34:80"},
    ],
    "assessment": {
        "consistency": "insufficient_evidence",
        "summary": "2 command(s) executed; 1 sensitive read; 1 external connect.",
        "evidence_ids": ["e2", "e3"],
        "suggested_next_step": "escalate",
        "uncertainties": ["No agent claim recorded."],
    },
}


class FormatTest(unittest.TestCase):
    def test_briefing_contains_key_fields(self):
        text = format_briefing(SAMPLE)
        self.assertIn("session-review-abc123", text)
        self.assertIn("読取 /home/ai-muse/canary-secret.txt", text)
        self.assertIn("接続 93.184.216.34:80", text)
        self.assertIn("証拠不足", text)          # consistency gloss
        self.assertIn("エスカレーション", text)    # next-step gloss
        self.assertIn("参考情報", text)            # advisory notice

    def test_flags_deduplicated(self):
        # two evidence_ids pointing at the same action render once
        sample = dict(SAMPLE)
        sample["assessment"] = {**SAMPLE["assessment"],
                                "evidence_ids": ["e2", "e2"]}
        text = format_briefing(sample)
        self.assertEqual(
            text.count("! 読取 /home/ai-muse/canary-secret.txt"), 1)

    def test_unavailable_summary_translated(self):
        sample = dict(SAMPLE)
        sample["assessment"] = {
            "consistency": "insufficient_evidence",
            "summary": "Guardian assessment unavailable; review the evidence "
                       "and claim manually.",
            "evidence_ids": [], "suggested_next_step": "review",
            "uncertainties": [],
        }
        text = format_briefing(sample)
        self.assertIn("手動で確認", text)


class SplitTest(unittest.TestCase):
    def test_short_message_single_chunk(self):
        self.assertEqual(len(split_message("hello")), 1)

    def test_long_message_chunked_within_limit(self):
        text = "\n".join(f"line {i} " + "x" * 100 for i in range(200))
        chunks = split_message(text)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(len(c), MAX_LEN)
        self.assertEqual("".join(chunks), text)


if __name__ == "__main__":
    unittest.main()
