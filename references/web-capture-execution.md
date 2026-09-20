# Web 采集执行合同

## 目标

把浏览器运行态转成可验证、可重放、可被 Builder 和 QA 消费的产物。模型自主选择 CDP、浏览器桥接或其他获准通道；选择标准是完整性和稳定性，不是固定命令序列。

## Capture Bundle

每个 page/scope/state/viewport/side 形成一个强 Capture Bundle，至少绑定：

- Project、Baseline、Scenario、page/scope、side；
- viewport、主题、语言、时区、角色和公开 location；
- environment、截图、DOM/AX 或等价结构；
- computed style/字体/资产 occurrence；
- state contract、动作见证与结果状态；
- 产物路径、SHA-256、schema 版本和采集来源。

Bundle 内上下文必须一致。路径存在和哈希匹配只是必要条件；内容必须可解码、schema 有效、公开信息策略合规且与 Scope/Spec 对得上。

## 采集原则

- 优先批量快照和浏览器运行态数据，避免对超大 DOM 逐节点远程调用。
- 每个状态从可复现起点进入，并保存状态前后见证；不要把三份同图改名为 default/hover/mobile。
- 资产 occurrence 只统计实际绘制范围；考虑 viewport、祖先 overflow 裁剪、遮挡和伪元素。
- 登录页面只保留公开可观察结构，输入值、Token、Cookie 和隐私文本必须剔除或脱敏。
- 参考端发现批次完成后冻结证据；首轮开发期间不反复刷新参考端追逐微小变化。

## 产物链

提供的脚本承担硬校验：

- `web_capture_*`：生成 Capture Bundle；
- `web_pipeline.py`：整理范围、Manifest 和规格输入；
- `web_fidelity_gate.py`：Builder/QA 两阶段门禁；
- `web_structure_diff.py`、`web_font_diff.py`、`web_visual_diff.py`：结构、字体和像素差异；
- `web_stability_gate.py`：两端自噪声与独立样本；
- `web_pair_analyzer.py`：将差异归因到可执行根因。

具体参数以各脚本 `--help` 为准；提示只维护合同，不复制命令手册。

## 失败闭锁

以下任一情况都应停止依赖该产物的严格 Builder/QA，并修复证据链：schema/上下文不匹配、文件被修改、强 Bundle 缺失、Manifest 与 occurrence 不一致、状态未真实触发、环境不稳定、截图不可解码、reference/replica 不独立、权利不满足。

失败闭锁只阻塞依赖范围，不必停止其他安全且无冲突的工作。
