from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BreadthFirstWavePolicyTests(unittest.TestCase):
    def test_skill_declares_wave_order_and_batch_barrier(self) -> None:
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for marker in (
            "DISCOVERY_SWEEP",
            "FIRST_PASS_BUILD",
            "BATCH_COMPARE",
            "CORRECTION_WAVE",
            "TASK-W1-QA-BATCH",
            "显式依赖本轮全部必需 Builder",
        ):
            self.assertIn(marker, skill)
        self.assertNotIn("Use this fixed loop for one Gap", skill)

    def test_browser_policy_prioritizes_click_drill_capture_before_code(self) -> None:
        protocol = (ROOT / "references" / "breadth-first-waves.md").read_text(encoding="utf-8")
        self.assertIn("控制面优先用于探索和留证", protocol)
        self.assertIn("按钮点击", protocol)
        self.assertIn("页面下钻", protocol)
        self.assertIn("立即保存截图", protocol)
        self.assertIn("先完成全范围首轮开发", protocol)
        self.assertIn("只在波次边界统一成对比对", protocol)

    def test_runtime_uses_dependencies_as_real_batch_barrier(self) -> None:
        runtime = (ROOT / "references" / "runtime-protocol.md").read_text(encoding="utf-8")
        self.assertIn("TASK-W1-BUILD-*", runtime)
        self.assertIn("TASK-W1-QA-BATCH", runtime)
        self.assertIn("explicit dependency", runtime)
        self.assertIn("will not make it runnable", runtime)

    def test_eval_covers_user_requested_workflow(self) -> None:
        data = json.loads((ROOT / "evals" / "evals.json").read_text(encoding="utf-8"))
        case = next(item for item in data["evals"] if item.get("id") == 39)
        self.assertIn("第一轮开发", case["prompt"])
        self.assertIn("batch QA task", case["expected_output"])
        self.assertGreaterEqual(len(case.get("expectations", [])), 5)


if __name__ == "__main__":
    unittest.main()
