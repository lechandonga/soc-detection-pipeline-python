# SOC 检测与关联告警流水线（本地模拟）

用本地事件与声明式规则模拟真实 SOC 的 **摄入 → 归一化 → 关联检测 → 去重/抑制
→ 告警生命周期 → 上下文富化 → 持久化重建** 闭环。设计目标是在事件乱序、重复、
规则变更与并发摄入下，检测结论 **确定、可解释、可复现**。

## 1. 架构

```
HTTP (FastAPI, soc/api.py)
        │
DetectionService (soc/service.py)   ← 单一 RLock 串行所有写操作
        │
 ┌──────┼───────────────────────────┬──────────────────────┐
ingestion   rules (不可变规则快照)   correlation (纯函数检测)  alerts (状态机)
归一化/校验   全量校验后原子替换       阈值/序列、窗口扫描         去重/抑制/生命周期
        │
enrichment（资产归属 + 威胁情报，未知/不可用显式标记）
        │
Store（soc/store.py）events.jsonl / alerts.jsonl 只追加；rules.json 原子落盘
```

关键确定性原则：

* 检测是 `(规则版本, rule_id, group_key, 按 (ts,seq,id) 排序的事件)` 的**纯函数**。
* 每个结论有稳定的 `match_key = sha256(rule_id|group_key|basis事件id)`，
  重放同一事件流得到相同 id，天然不会重复告警/重复计数。
* 所有可变状态只在一把锁内访问；规则集是不可变快照，整体校验通过后整体替换，
  正在进行的检测不可能看到"改了一半"的规则。

## 2. 运行与验证

```bash
uv sync                                  # 安装依赖
uv run pytest -q                         # 全部单测（45 个）
uv run pytest -q -o log_cli=true         # 同时打印输入与判定依据
uv run fastapi run main.py               # 启动服务
SOC_DATA_DIR=./data uv run fastapi run main.py   # 开启落盘持久化
```

测试覆盖：畸形事件（每种拒绝理由可区分）、乱序/重复、窗口半开边界、迟到事件、
规则非法加载与失败回滚、原子规则变更、生命周期非法跳转、抑制、并发摄入、
并发规则更新 + 告警变更、重启重放一致、容量上限、规则撤下（删除/停用收尾、
撤下后重启与重放一致、下线再上线不复活、撤下与人工并发、失败不留半套收尾）。
日志中每条用例都打印
`input=...` 与 `alert=... rule=... events=... basis(ts,seq)=...`。

## 3. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/events` | 摄入事件。201 接收；202 归档为 `too_late`；422 校验拒绝；409 重复 |
| GET  | `/api/v1/events/{id}` | 查询事件结论：accepted / too_late / unknown |
| GET  | `/api/v1/rules` | 当前不可变规则快照（含版本号） |
| PUT  | `/api/v1/rules` | 原子替换规则与抑制配置（非法整体拒绝，旧规则不动） |
| GET  | `/api/v1/alerts?state=` | 列出告警及其证据链。默认只列"没处理完"的（不含 closed）；`?state=closed` 查已关闭，`?state=all` 查全部 |
| GET  | `/api/v1/alerts/{id}` | 告警详情（证据、历史、富化上下文） |
| POST | `/api/v1/alerts/{id}/transition` | 生命周期动作 |

所有错误体形如：
`{"error": {"reason": "missing_field", "message": "...", "details": {...}}}`，
`reason` 是稳定的机器可读码（见 `soc/errors.py`）。

## 4. 事件格式与摄入语义

归一化字段（规则只允许引用这些字段 + `raw.<自定义字段>`）：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 字符串，全局唯一；重复 id 返回 409 `duplicate_event` |
| `source` | 是 | 必须属于已知来源：firewall/ids/edr/auth/webproxy/anti_virus，否则 `unknown_source` |
| `event_type` | 是 | 字符串 |
| `severity` | 是 | info/low/medium/high/critical |
| `ts` | 是 | epoch 秒（int/float）或 ISO-8601 文本（支持结尾 `Z`）；内部统一为 UTC epoch |
| `src_ip,dst_ip,user,host,action` | 否 | 必须为字符串 |
| 其它键 | 否 | 作为来源自定义 `raw` 标量字段（数量受 `max_raw_fields_per_event` 限制） |

拒绝理由互不相同：`malformed_payload`（非 JSON 对象/非法 JSON）、
`missing_field`、`invalid_field_value`、`invalid_timestamp`、
`event_too_far_in_future`（超过时钟偏斜）、`unknown_source`、
`duplicate_event`、`capacity_exceeded`。
**拒绝发生在任何写入之前**：不落日志、不改计数、不产生告警。

迟到策略：`cutoff = now - window_seconds - allowed_lateness_seconds`。

* `ts >= cutoff`：参与检测（即使乱序，也会按事件时间重排，结论一致）。
* `ts < cutoff`：结论固定为 `too_late`，写入日志可审计，但**永不参与检测**，
  因此"迟到事件如何处理"在任意重放/重启下结论相同、可复现。

## 5. 规则格式（声明式 JSON）

### 5.1 阈值规则

```json
{
  "id": "brute_force",
  "kind": "threshold",
  "name": "暴力破解",
  "count": 5,
  "window_seconds": 300,
  "group_by": ["host", "user"],
  "filters": [
    {"field": "event_type", "op": "eq", "value": "login_failed"},
    {"field": "severity", "op": "in", "value": ["high", "critical"]}
  ]
}
```

同一 `group_by` 键的事件，在任意半开窗口 `[t, t+window)` 内达到 `count` 即告警。
窗口可被规则覆盖，缺省用全局 `window_seconds`。

### 5.2 跨事件序列规则

```json
{
  "id": "priv_esc_chain",
  "kind": "sequence",
  "window_seconds": 600,
  "group_by": ["user"],
  "steps": [
    {"field": "action", "op": "eq", "value": "login"},
    {"field": "action", "op": "eq", "value": "sudo"},
    {"field": "action", "op": "eq", "value": "shadow_read"}
  ]
}
```

同一分组内，**按事件时间顺序**、在窗口内匹配全部步骤（事件可以乱序到达，
检测时自动按 `(ts, seq)` 排序）。采用贪心非重叠匹配，每个事件最多属于一次命中。

### 5.3 过滤器运算符

`eq, ne, in, notin, contains, prefix, regex, exists, gt, lt, gte, lte`
（数值比较作用于可转为数字的字段）。

### 5.4 加载期校验（先校验，再生效）

* 缺少 `id/kind`、未知 `kind`、非法运算符、阈值 `count<1`、序列步骤少于 2、
  窗口非正数等 → `invalid_rule`。
* 引用不存在的归一化字段 → `unknown_field_reference`（`raw.xxx` 形式除外）。
* 规则 id 重复 → `duplicate_rule`；规则数超 `max_rules` → `capacity_exceeded`。
* 配置整体是 all-or-nothing：任何一条非法，整个 PUT 被拒绝，线上规则保持不动。

### 5.5 抑制

```json
"suppressions": [
  {"id": "quiet_ci_hosts",
   "when": [{"field": "host", "op": "prefix", "value": "ci-"}]}
]
```

命中抑制条件的告警直接进入 `suppressed` 状态，并记录 `suppressed_by`。

## 6. 关联语义（去重 / 乱序 / 边界 / 迟到）

* **排序**：每个 lane 的事件按 `(ts, seq, id)` 全序排列；`seq` 是摄入序号，
  保证同时刻事件的先后不依赖线程调度。
* **窗口边界**：窗口为半开区间 `[start, start+window)`；恰好落在 `start+window`
  的事件**不**计入该窗口，行为确定且有测试固定。
* **阈值扫描**：左指针推进，窗口内满 `count` 即记录一次命中，basis 为前
  `count` 个事件，随后跳过该 basis 的首个事件继续滑动；重叠窗口共享事件是允许
  的，但相同 basis 集合对应唯一 `match_key`，绝不会生成两条告警。
* **序列匹配**：事件乱序到达不影响结论；同一批事件无论输入顺序如何，
  产生相同 `match_key` 集合（测试用随机洗牌验证）。
* **重复**：重复 id 在摄入期即以 `duplicate_event` 拒绝；引擎内部对相同 id
  再做一次去重（纵深防御）。
* **迟到**：截止线之外的事件固定 `too_late`，归档但不检测（见第 4 节）。
* **规则变更后回填**：原子替换规则后，用仍处于可关联时窗内的事件在新规则集上
  纯函数重算，已有结论按 `match_key` 去重，不会重复产生旧结论。

## 7. 告警生命周期

```
OPEN ──acknowledge──▶ ACKNOWLEDGED ──resolve──▶ RESOLVED
  │                      │                          │
  │                   unack                       reopen
  ▼                      ▼                          ▼
OPEN ◀──────────────────┘                         OPEN
  └──suppress──▶ SUPPRESSED ──unsuppress──▶ OPEN
任意非终态 ──close──▶ CLOSED（终态）
```

* 非法跳转（如 `RESOLVED → acknowledge`、对 `CLOSED` 的任何动作）返回 409
  `invalid_state_transition`，`details.allowed_from` 给出合法来源状态。
* 重复 `resolve` 幂等；`resolve → reopen → close` 连贯；`CLOSED` 为终态。
* 每次跳转都写入 `history`（action/ts/from/to/reason），并先追加命令日志再改内存。

## 8. 规则撤下（retirement）与收尾

规则调优的高频动作是"撤下"：**从配置里删除该规则**，或**保留配置但置
`enabled: false`**，两者语义相同。撤下通过常规的 `PUT /api/v1/rules`
原子替换生效，收尾结论确定：

* **统一收尾**：被撤规则此前产生的所有非终态告警（open/acknowledged/
  suppressed/resolved）在同一次规则替换内收敛为 `closed`，历史里记录
  `{"action": "close", "reason": "rule_retired", "rule_id": ...}`——
  与值班同学手动关闭（reason 为人工填写）明确区分。告警的状态取值与字段
  不变。
* **可查不可见**：收尾后的告警仍可按 id（`GET /api/v1/alerts/{id}`）和按
  状态（`?state=closed` / `?state=all`）查到，证据链、历史、计数完整保留；
  但默认列表（不带 `state`）只展示"没处理完"的告警，不再出现它们。
* **终态幂等**：已经是 `closed` 的告警不受撤下影响——不会被拖出终态，
  也不会追加第二条收尾记录；重复撤下同一规则是空操作。
* **不复活、不多算**：规则下线后再次上线，已收尾的告警保持 closed，
  相同事件结论（相同 `match_key`）不会复活旧告警、不会生成重复告警、
  计数不重算；只有真正的新事件才会在同一 lane 产生新告警（新 id）。
* **一致性**：收尾的 close 命令与告警创建一样先落 `alerts.jsonl` 再改内存，
  因此在线状态、重启重建、以及把同一份日志再重放一遍，三者逐条一致
  （状态、收尾原因、计数），与中间经历过多少次规则变更无关。
* **失败不留半套**：规则配置整体校验失败时整个 PUT 被拒绝，不发生任何
  收尾——旧规则、旧告警原样保留。
* **与人工并发**：撤下与人工 transition 都在同一把锁内串行化，每条告警
  只有先发生的那个结局生效（后到的人工动作按状态机拒绝或幂等空转），
  `history` 里的 from/to 链完整反映先后顺序；摄入在撤下期间照常进行。

本地验证：

```bash
uv run pytest -q tests/test_rule_retirement.py -o log_cli=true
```

## 9. 上下文富化

告警创建/追加出现时附带本地上下文：

* `asset`：按 `host` 查资产归属；`threat_intel`：按 `src_ip` 查威胁情报。
* 每个查询结果状态四选一，**显式区分、永不含糊**：
  `hit`（命中）/ `miss`（查过但无记录）/ `unknown`（事件缺字段）/
  `unavailable`（数据源故障）。
* 仅 `status == "hit"` 才令 `threat_hit / asset_hit` 为真；缺信息绝不会被
  当作命中，也不会被静默丢弃。

## 10. 持久化与重启重建

* `events.jsonl`：每条摄入尝试一行（accepted / too_late；被拒绝的不写）。
* `alerts.jsonl`：先落盘的告警创建与生命周期命令（含规则版本与 match_key）。
* `rules.json`：临时文件 + `os.replace` 原子写入。
* 重启时：加载规则 → 按 `seq` 顺序重放事件重建检测 lane → **按顺序重放
  告警命令日志**（create/transition）重建告警。告警以命令日志为准而非
  重新检测，因此被撤下规则留下的告警（含 `rule_retired` 收尾）在重建后
  原样保留。多次重建收敛到完全相同的告警、计数与状态；再次重放同一份
  日志也不会重复计数/重复告警/重复收尾。

## 11. 并发与容量

* 所有公共方法在同一把 `RLock` 内完成"校验 → 落盘 → 改内存"，跨请求不共享
  锁外可变对象；混合并发测试（8 线程摄入 + 持续规则替换 + 状态变更）验证
  无重复结论、无半更新、id 唯一。
* 可配置上限：`max_events / max_rules / max_alerts /
  max_raw_fields_per_event / max_group_scan`。超限时以 `capacity_exceeded`
  拒绝（告警容量通过无副作用"试检测"在落盘前预判），失败不残留事件、日志或
  告警；单 lane 事件超过 `max_group_scan` 时确定性丢弃最旧事件（降级）。
