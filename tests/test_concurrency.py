"""并发摄入 / 并发规则更新 / 告警状态变更同时发生：结果必须确定。"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import Config
from app.service import DetectionService

logger = logging.getLogger("soc.test.concurrency")

RULE = {
    "rule_id": "r1",
    "name": "阈值",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "threshold": {"count": 10, "window_seconds": 600, "event_types": ["evt"]},
}


def _ingest(svc, eid, t):
    return svc.ingest(
        {"event_id": eid, "source": "ids", "event_type": "evt",
         "severity": "high", "event_time": t, "src_ip": "10.0.0.1"}
    )


def test_concurrent_ingestion_no_double_count(tmp_path):
    svc = DetectionService(config=Config(data_dir=str(tmp_path)))
    svc.replace_rules([RULE])
    errors = []

    def worker(i):
        try:
            _ingest(svc, f"e{i}", float(i))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(worker, range(200)))
    assert errors == []
    stats = svc.stats()
    logger.info("200 线程并发摄入后统计=%s", stats)
    assert stats["events"] == 200
    # 阈值 10：第 10 条时触发一次，记录触发瞬间计数；之后不再重复告警
    alerts = svc.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["explanation"]["observed_count"] == 10
    assert len(alerts[0]["event_ids"]) == 10
    svc.close()


def test_concurrent_duplicates_are_idempotent(tmp_path):
    svc = DetectionService(config=Config(data_dir=str(tmp_path)))
    svc.replace_rules([RULE])
    accepted = []
    rejected_dup = {"n": 0}
    lock = threading.Lock()

    def worker():
        # 20 个线程反复提交相同 event_id
        try:
            svc.ingest(
                {"event_id": "same", "source": "ids", "event_type": "evt",
                 "severity": "high", "event_time": 1, "src_ip": "10.0.0.1"}
            )
            with lock:
                accepted.append(1)
        except Exception as exc:
            if getattr(exc, "reason", None) == "duplicate_event":
                with lock:
                    rejected_dup["n"] += 1
            else:
                raise

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    logger.info("相同事件并发: 接受=%d 重复拒绝=%d", len(accepted), rejected_dup["n"])
    assert len(accepted) == 1 and rejected_dup["n"] == 19
    assert svc.stats()["events"] == 1


def test_concurrent_rule_updates_never_half_updated(tmp_path):
    """并发全量替换规则 + 并发摄入：任意时刻读到的规则集合必须是完整的某一版。"""
    svc = DetectionService(config=Config(data_dir=str(tmp_path)))
    svc.replace_rules([RULE])
    stop = threading.Event()
    violations = []

    def updater():
        version = 0
        while not stop.is_set():
            version += 1
            rules = [
                {
                    "rule_id": f"r{version}",
                    "name": f"v{version}",
                    "rule_type": "threshold",
                    "group_by": ["src_ip"],
                    "threshold": {"count": 1, "window_seconds": 600,
                                  "event_types": [f"v{version}"]},
                }
            ]
            svc.replace_rules(rules)  # 要么成功整体生效，要么失败

    def observer():
        while not stop.is_set():
            snap = svc._registry.snapshot()
            # 不变量：恰有一个规则，rule_id 以 r 开头，规则内部字段自洽
            if len(snap) != 1:
                violations.append(("size", len(snap)))
                break
            (only,) = snap.values()
            if only.threshold is None or only.threshold.event_types != {f"{only.name}"}:
                violations.append(("shape", only.rule_id))
                break

    def ingester(i):
        try:
            svc.ingest(
                {"event_id": f"ce{i}", "source": "ids", "event_type": "evt",
                 "severity": "high", "event_time": i, "src_ip": "10.0.0.1"}
            )
        except Exception:  # noqa: BLE001,S110 并发压测下任何异常均不影响不变量检查
            pass  # 规则版本切换下被拒绝/不计数都可接受，但不得出现半更新断言失败

    pool = [threading.Thread(target=updater), threading.Thread(target=observer)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        for t in pool:
            t.start()
        list(ex.map(ingester, range(100)))
        stop.set()
        for t in pool:
            t.join()
    logger.info("并发规则更新不变量违规=%s 最终规则=%s", violations,
                list(svc._registry.snapshot()))
    assert violations == []
    svc.close()
