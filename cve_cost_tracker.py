"""
cve_cost_tracker.py — per-component / per-phase token & cost accounting.

Used by ``cve_agent.py --address <component>`` to attribute each Anthropic API
turn to a workflow phase (triage / exception / fix / close / plan), persist
results under ``reports/component_costs.json``, and print a summary when a
component run finishes.

Phases are inferred from the tools called in each turn (no reliance on the
model announcing phases).
"""

from __future__ import annotations

import json
import os
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
COST_REPORT_PATH = os.path.join(HERE, "reports", "component_costs.json")

# Workflow phases shown in summaries (order matters for display).
PHASES = ("triage", "exception", "fix", "close", "plan")

# Tool → default phase. reclassify_cve is special-cased by to_status.
_TOOL_PHASE = {
    "query_cve": "triage",
    "query_release": "triage",
    "analyse_upstream": "triage",
    "check_repo_version": "triage",
    "list_repo_tree": "triage",
    "analyse_component": "triage",
    "list_profiles": "triage",
    "read_local_file": "triage",
    "run_shell": "fix",
    "write_local_file": "fix",
    "apply_component": "fix",
}

# Priority when a single turn mixes tools (highest wins).
_PHASE_PRIORITY = {"fix": 4, "exception": 3, "close": 2, "triage": 1, "plan": 0}

_EMPTY_BUCKET = {"in": 0, "out": 0, "cache_w": 0, "cache_r": 0, "turns": 0}


def infer_phase(tool_uses) -> str:
    """Infer workflow phase from tool_use blocks in one assistant turn."""
    if not tool_uses:
        return "plan"
    best = "plan"
    best_pri = -1
    for b in tool_uses:
        name = getattr(b, "name", None) or (b.get("name") if isinstance(b, dict) else "")
        inp = getattr(b, "input", None)
        if inp is None and isinstance(b, dict):
            inp = b.get("input") or {}
        inp = inp or {}
        phase = "plan"
        if name == "reclassify_cve":
            st = str(inp.get("to_status") or "")
            if "Exception" in st:
                phase = "exception"
            elif "Closed" in st or st.lower() == "closed":
                phase = "close"
            else:
                phase = "close"
        elif name in _TOOL_PHASE:
            phase = _TOOL_PHASE[name]
        pri = _PHASE_PRIORITY.get(phase, 0)
        if pri > best_pri:
            best, best_pri = phase, pri
    return best


def _usage_delta_from_api(u) -> Dict[str, int]:
    return {
        "in": getattr(u, "input_tokens", 0) or 0,
        "out": getattr(u, "output_tokens", 0) or 0,
        "cache_w": getattr(u, "cache_creation_input_tokens", 0) or 0,
        "cache_r": getattr(u, "cache_read_input_tokens", 0) or 0,
    }


def _add_usage(dst: Dict, src: Dict) -> None:
    for k in ("in", "out", "cache_w", "cache_r", "turns"):
        dst[k] = dst.get(k, 0) + src.get(k, 0)


def cost_of_usage(usage: Dict[str, int], model: str, rates_for) -> float:
    """USD estimate for one usage bucket under ``model``."""
    ri, ro, rcw, rcr = rates_for(model)
    return (usage.get("in", 0) / 1e6 * ri
            + usage.get("out", 0) / 1e6 * ro
            + usage.get("cache_w", 0) / 1e6 * rcw
            + usage.get("cache_r", 0) / 1e6 * rcr)


class ComponentCostTracker:
    """Accumulate token/cost for one component run, broken down by phase."""

    def __init__(self, component: str, release: str = "",
                 rates_for=None):
        self.component = component
        self.release = release
        self.rates_for = rates_for
        self.started = time.time()
        self.by_phase: Dict[str, Dict] = {
            p: deepcopy(_EMPTY_BUCKET) for p in PHASES
        }
        # model → usage for this run
        self.by_model: Dict[str, Dict[str, int]] = {}
        self.turns = 0

    def record_turn(self, model: str, api_usage, tool_uses=None) -> str:
        """Attribute one Messages API response to a phase. Returns phase name."""
        phase = infer_phase(tool_uses or [])
        delta = _usage_delta_from_api(api_usage)
        delta["turns"] = 1
        _add_usage(self.by_phase.setdefault(phase, deepcopy(_EMPTY_BUCKET)), delta)
        m = self.by_model.setdefault(
            model, {"in": 0, "out": 0, "cache_w": 0, "cache_r": 0})
        for k in ("in", "out", "cache_w", "cache_r"):
            m[k] += delta[k]
        self.turns += 1
        return phase

    def totals(self) -> Dict[str, int]:
        t = deepcopy(_EMPTY_BUCKET)
        for p in self.by_phase.values():
            _add_usage(t, p)
        return t

    def cost(self) -> float:
        if self.by_model:
            return sum(u.get("cost", 0.0) for u in self.by_model.values())
        if not self.rates_for:
            return 0.0
        return sum(cost_of_usage(u, m, self.rates_for)
                   for m, u in self.by_model.items())

    def phase_cost(self, phase: str) -> float:
        """Approximate phase cost: weight total cost by phase input+output share.

        Exact per-phase cost needs per-turn model rates (we store by_model
        globally). We compute per-turn costs at record time when possible by
        using the last-recorded model proportions — simpler: store cost per
        phase as we go.
        """
        return self.by_phase.get(phase, {}).get("cost", 0.0)

    def record_turn_with_cost(self, model: str, api_usage, tool_uses=None) -> str:
        phase = infer_phase(tool_uses or [])
        delta = _usage_delta_from_api(api_usage)
        delta["turns"] = 1
        c = cost_of_usage(delta, model, self.rates_for) if self.rates_for else 0.0
        bucket = self.by_phase.setdefault(phase, deepcopy(_EMPTY_BUCKET))
        _add_usage(bucket, delta)
        bucket["cost"] = round(bucket.get("cost", 0.0) + c, 6)
        m = self.by_model.setdefault(
            model, {"in": 0, "out": 0, "cache_w": 0, "cache_r": 0, "cost": 0.0})
        for k in ("in", "out", "cache_w", "cache_r"):
            m[k] += delta[k]
        m["cost"] = round(m.get("cost", 0.0) + c, 6)
        self.turns += 1
        return phase

    def to_run_record(self) -> Dict:
        tot = self.totals()
        return {
            "component": self.component,
            "release": self.release,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "seconds": round(time.time() - self.started, 3),
            "turns": self.turns,
            "totals": {
                "in": tot["in"], "out": tot["out"],
                "cache_w": tot["cache_w"], "cache_r": tot["cache_r"],
                "cost": round(self.cost(), 6),
            },
            "by_model": {
                m: {**u, "cost": round(u.get("cost", 0.0), 6)}
                for m, u in self.by_model.items()
            },
            "by_phase": {
                p: {
                    "in": d.get("in", 0), "out": d.get("out", 0),
                    "cache_w": d.get("cache_w", 0), "cache_r": d.get("cache_r", 0),
                    "turns": d.get("turns", 0),
                    "cost": round(d.get("cost", 0.0), 6),
                }
                for p, d in self.by_phase.items()
                if d.get("turns") or d.get("in") or d.get("out")
            },
        }


def load_cost_store(path: str = COST_REPORT_PATH) -> Dict:
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except Exception:
            pass
    return {"components": {}}


def save_run(record: Dict, path: str = COST_REPORT_PATH) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    store = load_cost_store(path)
    comps = store.setdefault("components", {})
    name = record["component"]
    entry = comps.setdefault(name, {"runs": [], "lifetime": deepcopy(_EMPTY_BUCKET)})
    entry["runs"].append(record)
    # recompute lifetime from all runs
    life = deepcopy(_EMPTY_BUCKET)
    life["cost"] = 0.0
    life_phases: Dict[str, Dict] = {}
    for run in entry["runs"]:
        t = run.get("totals") or {}
        life["in"] += t.get("in", 0)
        life["out"] += t.get("out", 0)
        life["cache_w"] += t.get("cache_w", 0)
        life["cache_r"] += t.get("cache_r", 0)
        life["cost"] = round(life.get("cost", 0.0) + t.get("cost", 0.0), 6)
        for p, d in (run.get("by_phase") or {}).items():
            b = life_phases.setdefault(p, deepcopy(_EMPTY_BUCKET))
            b["cost"] = b.get("cost", 0.0)
            _add_usage(b, d)
            b["cost"] = round(b.get("cost", 0.0) + d.get("cost", 0.0), 6)
    entry["lifetime"] = life
    entry["lifetime_by_phase"] = {
        p: {**d, "cost": round(d.get("cost", 0.0), 6)}
        for p, d in life_phases.items()
    }
    entry["last_release"] = record.get("release")
    entry["last_completed_at"] = record.get("completed_at")
    store["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(store, fh, indent=2)
    os.replace(tmp, path)
    return path


def print_component_cost(record: Dict, store: Optional[Dict] = None) -> None:
    """Print this-run phase breakdown + all-components lifetime table."""
    name = record["component"]
    tot = record["totals"]
    print("\n" + "=" * 78)
    print(f"COST / TOKENS — component '{name}'  release={record.get('release')}")
    print("=" * 78)
    print(f"Turns: {record.get('turns', 0)}   "
          f"Wall time: {record.get('seconds', 0):.1f}s   "
          f"Cost: ~${tot.get('cost', 0):.4f}")
    print(f"Tokens: in={tot.get('in', 0)}  out={tot.get('out', 0)}  "
          f"cache_r={tot.get('cache_r', 0)}  cache_w={tot.get('cache_w', 0)}")

    print(f"\n{'PHASE':14}{'TURNS':>7}{'IN':>10}{'OUT':>10}"
          f"{'CACHE_R':>10}{'COST':>10}")
    print("-" * 61)
    for p in PHASES:
        d = (record.get("by_phase") or {}).get(p)
        if not d:
            continue
        cost_s = f"${d.get('cost', 0):.4f}"
        print(f"{p:14}{d.get('turns', 0):>7}{d.get('in', 0):>10}"
              f"{d.get('out', 0):>10}{d.get('cache_r', 0):>10}"
              f"{cost_s:>10}")
    print("-" * 61)
    tot_cost_s = f"${tot.get('cost', 0):.4f}"
    print(f"{'TOTAL':14}{record.get('turns', 0):>7}{tot.get('in', 0):>10}"
          f"{tot.get('out', 0):>10}{tot.get('cache_r', 0):>10}"
          f"{tot_cost_s:>10}")

    if record.get("by_model"):
        print("\nBy model (this run):")
        for m, u in record["by_model"].items():
            print(f"  {m}: in={u.get('in', 0)} out={u.get('out', 0)} "
                  f"~${u.get('cost', 0):.4f}")

    store = store or load_cost_store()
    comps = store.get("components") or {}
    if comps:
        print("\n" + "=" * 78)
        print("ALL COMPONENTS (lifetime across --address runs)")
        print("=" * 78)
        print(f"{'COMPONENT':20}{'RUNS':>6}{'IN':>10}{'OUT':>10}{'COST':>10}")
        print("-" * 56)
        grand = 0.0
        for cname, entry in sorted(
                comps.items(),
                key=lambda kv: -(kv[1].get("lifetime") or {}).get("cost", 0)):
            life = entry.get("lifetime") or {}
            nruns = len(entry.get("runs") or [])
            c = life.get("cost", 0.0)
            grand += c
            cs = f"${c:.4f}"
            print(f"{cname:20}{nruns:>6}{life.get('in', 0):>10}"
                  f"{life.get('out', 0):>10}{cs:>10}")
        print("-" * 56)
        gs = f"${grand:.4f}"
        print(f"{'GRAND TOTAL':20}{'':6}{'':10}{'':10}{gs:>10}")

        # Per-component phase rollup for completed ones
        print(f"\n{'COMPONENT':16}{'TRIAGE':>9}{'EXCEPT':>9}{'FIX':>9}"
              f"{'CLOSE':>9}{'PLAN':>9}")
        print("-" * 61)
        for cname, entry in sorted(comps.items()):
            lp = entry.get("lifetime_by_phase") or {}
            cells = []
            for p in PHASES:
                c = (lp.get(p) or {}).get("cost", 0.0)
                cells.append(f"${c:.3f}" if c else "-")
            print(f"{cname:16}{cells[0]:>9}{cells[1]:>9}{cells[2]:>9}"
                  f"{cells[3]:>9}{cells[4]:>9}")


def print_all_costs(path: str = COST_REPORT_PATH) -> None:
    store = load_cost_store(path)
    if not store.get("components"):
        print("No component cost data yet. Run: "
              "python3 cve_agent.py --address <component>")
        return
    # Fake a zero record so we only print the all-components section via a
    # lightweight printer.
    print("\n" + "=" * 78)
    print(f"COMPONENT COST REPORT  ({path})")
    print(f"Updated: {store.get('updated_at', '?')}")
    print("=" * 78)
    comps = store["components"]
    print(f"{'COMPONENT':20}{'RUNS':>6}{'IN':>10}{'OUT':>10}{'COST':>10}")
    print("-" * 56)
    grand = 0.0
    for cname, entry in sorted(
            comps.items(),
            key=lambda kv: -(kv[1].get("lifetime") or {}).get("cost", 0)):
        life = entry.get("lifetime") or {}
        nruns = len(entry.get("runs") or [])
        c = life.get("cost", 0.0)
        grand += c
        cs = f"${c:.4f}"
        print(f"{cname:20}{nruns:>6}{life.get('in', 0):>10}"
              f"{life.get('out', 0):>10}{cs:>10}")
    print("-" * 56)
    gs = f"${grand:.4f}"
    print(f"{'GRAND TOTAL':20}{'':6}{'':10}{'':10}{gs:>10}")
    print(f"\n{'COMPONENT':16}{'TRIAGE':>9}{'EXCEPT':>9}{'FIX':>9}"
          f"{'CLOSE':>9}{'PLAN':>9}")
    print("-" * 61)
    for cname, entry in sorted(comps.items()):
        lp = entry.get("lifetime_by_phase") or {}
        cells = []
        for p in PHASES:
            c = (lp.get(p) or {}).get("cost", 0.0)
            cells.append(f"${c:.3f}" if c else "-")
        print(f"{cname:16}{cells[0]:>9}{cells[1]:>9}{cells[2]:>9}"
              f"{cells[3]:>9}{cells[4]:>9}")
    # Detail last run per component
    print("\nLast run per component:")
    for cname, entry in sorted(comps.items()):
        runs = entry.get("runs") or []
        if not runs:
            continue
        last = runs[-1]
        print(f"  {cname}: release={last.get('release')}  "
              f"~${(last.get('totals') or {}).get('cost', 0):.4f}  "
              f"at {last.get('completed_at')}")
