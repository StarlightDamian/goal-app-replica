# Web 保真与资产合同

## 1. 保真等级

- `functional`：行为、状态、权限、错误和接口等价；视觉只需不妨碍使用。
- `visual`：关键结构、布局、Token、字体与授权资产在声明容差内。
- `pixel`：在固定环境、视口和状态下，关键区域或整页通过稳定且可重算的精确像素门禁。

只对已声明 Scenario 和范围作完成声明；截图输入不能证明隐藏 DOM、源码或内部架构。

## 2. 真值与权利

优先级：

1. 用户拥有/许可的源码、设计和资源；
2. 获准观察的运行时 DOM、AX、computed/matched style、字体和公开网络行为；
3. 截图推断。

每个可见资产记录来源、权利、哈希、出现位置、状态和变体。`reference_only` 或权利未知的 Logo、商业图片、字体和视频不得复制、热链或生成相似替代物冒充一比一；这类范围最多完成结构/行为等价，并保持 visual/pixel Gap 打开。

## 3. 发现范围

Discovery Matrix 应覆盖必需 viewport × state，而不只是默认桌面截图。重点包括：

- responsive、scroll/sticky/overlay/stacking；
- hover/focus/active/disabled/loading/empty/error/permission；
- `img/srcset/picture`、CSS 背景、伪元素、SVG、canvas、Icon、字体与视频；
- 实际绘制可见性，包含祖先裁剪和遮挡，不能把非零 bounding box 当作可见。

## 4. Foundation 与首轮实现

先稳定环境和 reference self-noise，再建立页面拓扑、全局 Token、字体/资产 Manifest、共享组件和组件规格。Builder 的范围应覆盖真实 Render Boundary，而不是孤立的文字节点。

默认首轮顺序：环境 → 页面骨架 → 共享系统 → 页面模块 → 状态/边界 → 批量比较。局部 leaf fix 只有在 Diff 指向时才值得单独处理。

## 5. 两阶段门禁

- Builder Gate：证明参考捕获、范围、规格、资产权利和输入产物可信；不要求实现前已有“通过的复刻截图”。
- QA Gate：实现后独立验证复刻捕获、结构/字体/视觉 Diff 和稳定性；不得信任报告自带的 `pass` 或 metrics，必须从原始产物重算。

`web_foundation` 只产出证据/规格，不编辑产品代码。严格 Web Builder 必须依赖对应 Foundation 和有效 preflight。权利受限时可使用 structure-only Builder，但不能关闭 visual/pixel Gap。

## 6. 禁止的假通过

以下均不能支持 visual/pixel 完成：

- 空 DOM/AX/environment、不可解码 PNG、仅路径/哈希正确；
- 同一文件冒充 reference/replica；
- 复制截图改名为不同状态或视口；
- 单次动态截图、非零 self-noise；
- 空 Asset Manifest、猜测 SVG/Icon、AI 近似图；
- 全局相似度或高 channel threshold 吞掉真实差异；
- Canva/Figma 导入结果被当作 DOM/CSS 或采集真值。

设计工具可辅助评审和用户提供的源设计，但不能替代运行时证据或解锁 Gate。
