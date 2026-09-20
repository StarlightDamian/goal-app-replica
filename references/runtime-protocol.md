# Goal 运行协议

## 1. 唯一真值

每个项目绑定：稳定 Project ID、参考身份、复刻代码根、范围、授权、保真等级和资源集合。持久状态至少包含：

- `phase`：当前波次；
- `run_state`：`active | paused | blocked | complete | stopped`；
- Baseline、Scenario、Evidence、Gap、Task、Lease、Handoff、Checkpoint；
- 环境/身份指纹与下一步。

聊天只用于协作；Controller 状态与哈希产物是恢复真值。

## 2. 进入方式

- `START`：不存在匹配项目时新建，不覆盖旧状态。
- `RESUME`：身份与范围匹配时恢复租约、进程、会话、设备和可运行任务。
- `RECOVER`：状态缺失或损坏时先盘点，不直接接管不明资源。
- `REBASELINE`：参考版本、角色、数据、主题、视口或设备变化时建立新 Baseline，并只使依赖证据失效。

失败的 RESUME 不得静默变成 START。显示名相似不等于同一项目。

## 3. 状态机

```text
BOOTSTRAP → DISCOVERY_SWEEP → FIRST_PASS_BUILD
→ BATCH_COMPARE → CORRECTION_WAVE_n → BATCH_VERIFY → COMPLETE
```

页面结果属于 Scenario/Gap；全局 `phase` 描述主导波次，不创建“页面 A 已像素完成”的全局阶段。

任务：`ready → claimed → review → done`，也可通过 handoff 回到 `ready` 或进入 `blocked`。任务完成与 Gap 关闭是两件事；Gap 仅由独立 QA 或 accepted deviation 关闭。

## 4. 真实批量屏障

首轮任务采用稳定命名和依赖图：

```text
TASK-W1-BUILD-* ─────┐
TASK-W1-BUILD-* ─────┼→ TASK-W1-QA-BATCH
TASK-W1-BUILD-* ─────┘
```

`TASK-W1-QA-BATCH` 必须对每个必需首轮 Builder 建立 **explicit dependency**。A prose claim that the round is complete **will not make it runnable**。新增必需 Builder 时同步更新屏障；阻塞任务必须有可审查 blocker，而不是从依赖图消失。

## 5. 资源与所有权

任务在执行前原子领取所需资源。资源键应能表达冲突，例如：项目、参考/复刻控制面、浏览器 profile、设备/模拟器、端口、网络路线、代码目录、全局 Token、资产 Manifest、组件规格和 Gap。

原则：

- 一个交互控制面只有一个活动 Owner。
- 并行写同一代码边界必须串行；不同项目、设备和会话必须隔离。
- 租约含 owner、epoch、心跳、到期时间和资源；所有权变化或心跳失败后立即停止写入。
- 到期不等于无人使用，只有确认进程/Agent/工作树失活后才能 reap。
- Handoff 必须独立于聊天，包含改动、验证、证据、不确定性和下一步。

## 6. 调度

优先选择能最大化 Goal 进展且不破坏波次的任务：

1. P0 安全/环境/构建阻塞；
2. 当前波次的共享前置项；
3. 能解锁多个范围的工作；
4. P1 必需 Scenario；
5. P2 局部优化。

局部任务阻塞时继续其他无冲突任务。只有授权、身份、参考环境或基础工具链的全局失败才把整个 Goal 标记 blocked。

Agent Team 仅在并行、隔离或独立复核有净收益时使用。Coordinator 维护状态、依赖和合并；Surface Owner 控制参考端；Builder 按边界写代码；QA 不编辑被验收的产品代码。

## 7. 检查点与完成

在进入/离开波次、接受 handoff、变更 Baseline、产生全局 blocker 或结束会话时写 Checkpoint。它应说明：当前阶段、已完成范围、开放 Gap、脏文件/进程、证据、阻塞和唯一下一步。

Controller CLI 的具体参数以 `scripts/replica_ctl.py --help` 为准；不要在模型提示中复制一份易漂移的命令手册。
