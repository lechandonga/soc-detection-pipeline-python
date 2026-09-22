# 本地 SOC 检测与关联告警管线

用本地事件与规则配置模拟真实 SOC 的「摄入 → 归一化 → 规则加载 → 面向事件时间的窗口关联 →
去重/抑制 → 告警生命周期 → 本地上下文补充 → 持久化与重建」闭环。面向**事件乱序、重复、
规则变更与并发摄入**，保证检测结论一致、可复现、可解释。

## 1. 架构与模块

| 模块 | 职责 |
| --- | --- |
| `app/ingestion.py` | 事件严格校验与归一化（纯函数，失败无副作用） |
| `app/rules.py` | 声明式规则的加载校验、不可变快照、原子全量替换 |
| `app/correlation.py` | 面向 event_time 的阈值/序列关联（两阶段 plan/commit） |
| `app/alerts.py` | 告警去重、抑制、生命周期状态机 |
| `app/context.py` | 资产归属与威胁情报补充（缺失显式标记） |
| `app/storage.py` | 每行一个 JSON 的仅追加 WAL（fsync、半行忽略） |
| `app/service.py` | 编排门面：锁、两阶段提交、WAL 先行、重启重建/重放 |
| `app/api.py` | HTTP 层，把领域异常映射为带稳定 `reason` 的响应 |
| `main.py` | 服务入口（`uvicorn main:app`） |

## 2. 快速开始

```bash
uv sync
uv run uvicorn main:app --reload        # 启动（默认 ./data 下维护 WAL）
# 可选：SOC_CONFIG=examples/config.json SOC_DATA_DIR=./data uv run uvicorn main:app
```

```bash
# 加载/替换规则（全量原子替换）
curl -s -X PUT localhost:8000/rules -H 'content-type: application/json' \
  --data @examples/rules.json

# 摄入事件
curl -s -X POST localhost:8000/events -H 'content-type: application/json' \
  --data @examples/events.jsonl        # 逐条发送（每行一个事件）

# 查询与流转
curl -s localhost:8000/alerts
curl -s localhost:8000/alerts/<alert_id>
curl -s -X POST localhost:8000/alerts/<alert_id>/transition \
  -H 'content-type: application/json' -d '{"action":"resolve"}'
curl -s -X POST localhost:8000/replay   # 从 WAL 重建并重放
```

## 3. 事件格式与摄入拒绝原因

事件为 JSON 对象。必填：`event_id`、`source`、`event_type`、`severity`（非空字符串）、
`event_time`；可选：`src_ip`、`dst_ip`、`user`、`asset_id`、`attrs`（标量键值对象）。

- 时间接受：epoch 秒（int/float，允许 0、负数）、带时区的 ISO-8601（含末尾 `Z`）。
  无法解析、**朴素时间戳（缺时区，语义有歧义）**、NaN/无穷一律拒绝。
- `source` 必须在白名单：`firewall / ids / edr / auth / web_proxy / dlp`。

拒绝都返回 HTTP 422 并带稳定 `reason`（可区分、可断言）：

| reason | 含义 |
| --- | --- |
| `missing_field` | 必填字段缺失或为 null |
| `invalid_payload` | 字段类型/形态非法（空字符串、attrs 非标量、请求体非对象、坏 JSON） |
| `invalid_time` | 时间无法解析/无时区/非有限数 |
| `unknown_source` | 来源不在白名单 |
| `duplicate_event` | `event_id` 已存在（HTTP 422，不重复计数） |
| `event_limit_exceeded` / `group_limit_exceeded` / `alert_limit_exceeded` | 规模上限（HTTP 429） |

**无部分写入**：摄入流程是「校验 → 重复/上限预检查 → 纯判定 plan（不改状态）→
WAL append+fsync → 内存 commit」。任何在 WAL 之前的失败都不触碰内存与磁盘。

## 4. 规则格式

顶层字段：`rule_id`、`name`、`rule_type`（`threshold` / `sequence`）、
`group_by`（字段引用数组）、可选 `suppression_key`、判据主体。

字段引用域（引用域之外的名字在**加载阶段**以 `unknown_field_reference` 拒绝）：

- 公共字段：`event_id, source, event_type, event_time, severity, src_ip, dst_ip, user, asset_id`
- 扩展属性：`attr.<name>`

### 4.1 阈值规则

```json
{
  "rule_id": "brute-force",
  "rule_type": "threshold",
  "group_by": ["src_ip"],
  "suppression_key": ["src_ip"],
  "threshold": {
    "count": 5,
    "window_seconds": 300,
    "event_types": ["ssh.auth_fail"],
    "filter_attr": "attr.signature_id",
    "filter_value": "S-1",
    "align_window": true
  }
}
```

- 窗口为**左闭右开** `[k·W, (k+1)·W)` 的对齐窗口（`align_window=true`，默认），边界归属确定；
  `false` 时为以当前事件为右端点的滑动窗口。
- 同一分组同一窗口达到 `count` **只产生一次告警**；命中解释含窗口、观测计数、阈值、命中事件 id。
- `event_types` 省略表示不限类型；`filter_attr/filter_value` 为可选等值过滤。

### 4.2 序列规则

```json
{
  "rule_id": "kill-chain",
  "rule_type": "sequence",
  "group_by": ["src_ip", "dst_ip"],
  "sequence": {
    "window_seconds": 600,
    "steps": [
      {"name": "scan", "event_type": "port.scan"},
      {"name": "login", "event_type": "ssh.auth_ok"}
    ]
  }
}
```

- 按 **event_time** 排序匹配（等时间戳用 `event_id` 字典序打破并列），因此**乱序到达等价**：
  先到「登录」后到「扫描」，只要事件时间顺序满足，仍命中。
- 首末事件跨度必须 `<= window_seconds`；至少 2 个步骤；步骤名不可重复。

规则非法（结构、计数/窗口非正、类型未知、步骤不足、`rule_id` 重复等）一律加载阶段拒绝
（`invalid_rule_config`），整体校验通过前绝不发布，故运行中的检测永远看不到「更新到一半」的集合。

## 5. 关联语义（乱序 / 重复 / 边界 / 迟到）

1. 一切判定基于 `event_time`，与请求到达顺序无关；同一事件流以任意（在迟到宽限内的）
   顺序注入，命中集合相同（见 `test_shuffled_stream_same_conclusion`）。
2. 重复事件（相同 `event_id`）在摄入层即以 `duplicate_event` 拒绝，绝不进入计数。
3. **Watermark 迟到裁决**：`watermark = 已观测最大 event_time - allowed_lateness_seconds`。
   `event_time < watermark` 的迟到事件**确定地不参与关联**，响应 `verdict="late_ignored"`，
   但仍持久化；结论可复现（相同流相同顺序结论恒同）。
4. 阈值窗口左闭右开，边界事件归属唯一；命中去重键 `(threshold, rule, group, window_idx)`，
   每窗口最多一次。序列命中键为匹配到的事件 id 有序元组，重复扫描不重复命中。

> 注意：迟到裁决依赖注入顺序中的水位推进。「顺序无关」指在允许迟到宽限之内，任意乱序
> 注入结论一致；早于水位的超迟到事件按上述确定策略处理而不是回溯改历史告警。

### 规则变更对进行中窗口的影响（确定性策略）

规则集合全量替换成功后：新规则立即对后续事件生效；**进行中的关联窗口按新集合重新开始**
（引擎窗口历史重置，watermark 归零），已产生的告警与其历史完整保留、不受影响。
该动作同样先写 WAL 再生效，因此实时路径与重启重放走同一条代码路径，结论一致。

## 6. 告警去重、抑制与生命周期

- **去重**：告警 ID 由命中去重键做稳定 SHA-256 派生（`al-xxxx…`）。同一命中无论重放多少次
  都是同一条告警，重复重放不重复计数/告警。
- **抑制**：新命中若与同规则下仍活动（open/suppressed）告警的**非空且不含 null** 的
  `suppression_key` 元组相同，则新告警以 `suppressed` 产生并记录 `suppressed_by`。
- 合法状态流转：

```
OPEN ──suppress──▶ SUPPRESSED ──unsuppress──▶ OPEN
OPEN ──resolve──▶ RESOLVED ──close──▶ CLOSED   （CLOSED 为终态）
```

非法跳转返回 HTTP 409，`reason` 可区分：

| reason | 场景 |
| --- | --- |
| `must_resolve_before_close` | OPEN 直接 close（必须先 resolve，保证恢复→关闭连贯） |
| `suppressed_must_reopen_before_resolve` | SUPPRESSED 直接 resolve |
| `resolved_must_close_first` | RESOLVED 回退 OPEN |
| `closed_is_terminal` | CLOSED 再做任何流转 |
| `same_status_no_op` | 流转到当前状态 |
| `unknown_action` / `alert_not_found` | 动作未知 / 告警不存在（404） |

## 7. 本地上下文补充

`ContextEnricher(assets, intel, intel_available)`：按 `asset_id` 查归属（owner/criticality），
按 `src_ip`（备选 `dst_ip`）做情报精确匹配。缺失信息**显式标记**，绝不静默丢弃，也不当命中：

- 资产查不到：`owner/criticality = "UNKNOWN"`
- 情报源可用且未命中：`{"hit": false}`；命中：`{"hit": true, "detail": "indicator:<ip>"}`
- 情报源不可用（`intel_available=false`）：`"NOT_AVAILABLE"`（不可用 ≠ 未命中）

## 8. 持久化、重启与重放

- 所有状态变更（规则替换、已接受事件、告警流转）在内存生效前先追加到
  `data/wal.jsonl` 并 `flush+fsync`；每行一个完整 JSON，崩溃残留半行在重放时确定性忽略。
- 启动时按 WAL 顺序重放重建规则、关联状态、告警（含状态历史）。
- `POST /replay` 以 WAL 为唯一事实源从零重建；重复执行幂等：事件数、告警数、
  告警 ID 与状态轨迹完全相同。

## 9. 规模上限与降级策略

在 `examples/config.json` 配置，超限在**任何写入前**拒绝（HTTP 429），不残留中间状态：

- `max_events`：已接受事件总数 → `event_limit_exceeded`
- `max_rules`：单次规则集合条数 → `rule_limit_exceeded`
- `max_alerts`：将新建的告警数（去重命中不计）→ `alert_limit_exceeded`
- `max_group_members`：单规则分组窗口历史事件数 → `group_limit_exceeded`
  （达到上限拒绝写入，而非静默丢弃，避免计数错乱）

## 10. 并发正确性

- 服务内一把 `threading.RLock` 串行化所有状态变更；FastAPI 线程池并发请求在状态层面互斥，
  杜绝跨请求共享可变状态串扰。
- 规则为不可变对象 + 快照引用原子替换；检测进入时抓取快照并全程使用，不观测半更新集合。
- 事件处理两阶段 plan/commit，WAL 成功后才改内存；并发相同 `event_id` 恰好一次接受，
  其余全部 `duplicate_event`。

## 11. 验证方法

```bash
uv run ruff check app main.py tests     # 静态检查
uv run pytest -q                        # 52 个用例
uv run pytest -s                        # 同时打印每个用例的「输入 + 判定依据」日志
```

测试覆盖（`tests/`）：

- `test_ingestion_malformed.py`：11 类畸形输入的可区分拒绝 + 失败不留状态
- `test_correlation_ordering.py`：乱序、窗口边界、多次乱序结论一致、重复、迟到、序列
- `test_rule_updates.py`：非法规则加载拒绝、引用未知字段、更新原子性、超限、跨重启
- `test_alert_lifecycle.py`：去重、抑制、合法轨迹、5 类非法跳转原因、重启连贯
- `test_context_and_recovery.py`：UNKNOWN / NOT_AVAILABLE / 命中、重启一致、重放幂等
- `test_concurrency.py`：200 并发摄入不重复计数、同 id 并发恰好一次、并发规则更新无半更新
- `test_limits.py`：事件/告警/分组上限拒绝且无残留

## 12. HTTP 接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /health` | 健康与计数（events/rules/alerts/watermark） |
| `POST /events` | 摄入并检测，返回 `status/verdict/watermark/alerts` |
| `PUT /rules` | 全量原子替换规则集合 |
| `GET /alerts`、`GET /alerts/{id}` | 列表/详情（含解释与状态历史） |
| `POST /alerts/{id}/transition` | 状态流转，body：`{"action": "suppress|unsuppress|resolve|close"}` |
| `POST /replay` | 从 WAL 重建并重放，返回重放计数摘要 |
