# PLAN: libmpv 原生海报生成（后续启动）

日期: 2026-11-15
前置报告: `docs/MPV_POSTER_EVAL.md`
状态: **已实施（2026-11-15 同日）**；ffmpeg CLI 后端已删除

## 0. 实施结果（与下方原计划的差异）

计划是按"可选后端 + 保留 ffmpeg 回落"写的；实际决定改为**直接替换**，因此与计划第 2、3 节不同：

- **ffmpeg CLI 后端整个删除**：`lib/utils/ffmpeg_thumb_args.dart`、桌面
  `Process.run('ffmpeg', …)` 路径、依赖它的测试与文档全部移除。libmpv 比它快
  （1280×720 warm 帧 47–88 ms 对 111–150 ms；本次在 640×853 竖屏上实测
  seek 0 ms + frame 49 ms + encode 63 ms）且不需要 PATH 上的外部程序。
- **分级从"desktop/mobile"改为按后端命名**：`utils/poster_backend.dart` 的
  `PosterBackend` 只有两个值 —— `libmpv`（libmpv 自己渲染，iOS 以外的所有平台）
  和 `mpv`（media_kit 的 `Player.screenshot` + Rust 编码，iOS，以及没有该导出的
  旧 bridge）。`ThumbnailService` 不再按平台分叉。
- **特性拆分**：新增 `libmpv-poster`（`libmpv.rs` + `libmpv_poster.rs` +
  `rcrm_generate_poster_async` + `libloading`）；原 `mpv-poster` 保持不动，仍只负责
  iOS 的截图编码。桌面脚本默认启用 `libmpv-poster`，iOS 故意不启用。
- **复用**：blank band / 不透明 alpha / WebP 编码都在 `poster.rs`，两条后端共用；
  `webp.rs` 新增 `encode_bgra`（原地编码，无通道交换）并与 `encode_rgba` 共用一个
  编码函数；`webpBufBytes` 统一了 Dart 侧所有 `WebpBuf*` 的零拷贝包装。
- **并发**：桌面 11 → 4（每个槽现在是一个完整的 mpv 解码上下文）。
- **未做**：libmpv context 跨 job 复用（每个 poster 一个 context，job 内跨位置复用）、
  独立 helper 进程隔离崩溃、许可证结论。

## 1. 目标

- 在 Rust 进程内动态加载 libmpv，用软件渲染直接生成视频海报；
- 帧写入 Rust native buffer，blank/resize/WebP 均在 Rust 完成，不经过 Dart；
- 桌面端可选替代 ffmpeg CLI；移动端评估是否用于替换 media_kit screenshot 路径；
- 始终保留现有 ffmpeg / media_kit 回落。

## 2. 非目标

- 本轮不删除 ffmpeg CLI；
- 不在 iOS 上动态加载 libmpv；
- 不改动现有 `mpv-poster` 特性（media_kit screenshot + Rust 编码）；
- 不重写播放器或 media_kit 的播放路径。

## 3. 关键决策

1. 新增独立 Cargo feature **`libmpv-poster`**，不复用 `mpv-poster`。
2. 默认关闭；桌面构建可选开启，A/B 通过后再考虑默认。
3. 平台顺序: Windows -> Linux/macOS -> Android；iOS 排除。
4. 任何初始化/seek/render/encode 失败立即回落现有后端，不让海报卡死。
5. 崩溃隔离未解决前，不把 libmpv 设为唯一桌面后端。

## 4. 阶段

### Phase 0: 原型（已完成）

- 已验证 `MPV_RENDER_API_TYPE_SW` + `bgr0` + Rust WebP 可行；
- 已验证 native buffer 零拷贝帧传递；
- 已测 warm 帧比 ffmpeg 快约 1.2-2.4 倍；
- 已定位 seek/render 同步、aspect、alpha 等坑。

### Phase 1: Rust 后端骨架

- 新文件 `crates/rcrm-flutter-bridge/src/libmpv_poster.rs`（名字可调）。
- Cargo: `libmpv-poster = ["dep:libloading"]`；`libloading` 仅该 feature 启用。
- 动态库发现:
  - Windows: 可执行文件目录的 `libmpv-2.dll`；
  - Linux: `libmpv.so.2` / `libmpv.so`；
  - macOS: `libmpv.dylib`；
  - 失败返回可区分的错误码。
- 校验 `mpv_client_api_version`，不满足最低版本直接失败回落。
- `MpvPoster` 结构持有 handle、render context、event loop 线程和 native buffer。
- 选项: `vo=libmpv`, `hwdec=no`, `audio=no`, `sub=no`, `pause=yes`, `keep-open=yes`, `config=no`, `terminal=no`, `input-default-bindings=no`, `osd-level=0`。

### Phase 2: 正确的帧协议

- 视频尺寸: 读取 `width`/`height`（或 `video-params`），按 `target_h = round(640 * h / w)` 分配 SW 目标。
- seek 前: drain events，调用 `mpv_render_context_update`；若 FRAME 则 render + `mpv_render_context_report_swap` 消费旧帧。
- seek: `absolute+exact`（或按产品需要 keyframe）；等待 `MPV_EVENT_SEEK` (20)。
- 轮询 `mpv_render_context_update` 直到 `MPV_RENDER_UPDATE_FRAME`；超时失败。
- `mpv_render_context_render` 写入 native buffer；`report_swap`。
- 校验 `time-pos` 与目标位置的偏差；超差则重试/回落。
- 处理 `MPV_EVENT_END_FILE`、错误事件、取消、context dispose。

### Phase 3: 零拷贝编码

- 新增 BGRA 不透明 WebP 编码路径: zenwebp `PixelLayout::Bgra8`；
- alpha 255 与 blank/luma 合并为一次原地遍历；
- 目标尺寸已由 mpv 输出，不再调用 `downscale_bgra_opaque_bilinear`；
- 返回 `WebpBuf`；Dart 侧只拿 finalizer 视图。

### Phase 4: Dart 接入与 A/B

- 新 worker/service 入口，例如 `MpvNativePoster`，不塞进 `ThumbWebpWorker` 的现有 op（该 worker 是 WebP 编码器，不是播放器）。
- Rust FFI 导出建议: `rcrm_generate_poster_libmpv(url, headers, positions, target_width, ...)`；同步调用放专用 isolate，或 Rust 内部线程 + 回调。
- `ThumbnailService._posterDesktop` 增加后端选择: `libmpv` 优先（若可用）-> ffmpeg 回落；`POSTER|backend=libmpv|...` 日志。
- 保持现有 poster 队列、暂停/恢复、in-flight 去重、缓存语义不变。
- 移动端先不接，等桌面 A/B 结论。

### Phase 5: 基准与上线

- 真实 WebDAV HTTP + HTTPS（自签）测试；
- 4K / HEVC / 长 GOP / 竖屏 / 超宽；
- 1/2/4/8 路并发，记录吞吐、CPU、RSS；
- 冷启动 vs warm 帧 vs 首帧；
- 坏文件/超时/取消/网络中断；
- 与 ffmpeg 的帧正确性（MAD <= 5）和视觉抽查。

## 5. 验收门槛

- 帧正确性: 与 ffmpeg 同位置 MAD <= 5（WebP 有损），无旧帧；
- 功能: 所有现有海报测试、缓存、暂停/恢复、刷新路径通过；
- 回落: 动态库缺失、版本不匹配、seek 超时、编码失败都自动回 ffmpeg；
- 性能: 真实网络 + 4 路并发下，libmpv 总耗时中位数至少比 ffmpeg 快 1.3 倍，或内存/CPU 明显更优；
- 稳定性: 连续 100 个不同视频/位置无崩溃、无泄漏；
- 合规: libmpv 许可证与 TLS 策略经确认。

## 6. 明确不通过就停止的条件

- 真实网络下不如 ffmpeg，或并发下差距消失；
- 需要大幅提高并发内存，超出 96/512 MB 缓存预算的收益；
- 许可证无法接受；
- 无法解决进程内崩溃风险且产品不接受；
- iOS 需求成为硬性要求（当前方案不覆盖）。

## 7. 回滚

- 运行时: `libmpv-poster` 未启用或初始化失败 -> 现有 ffmpeg / media_kit 路径；
- 发布: 保留 feature 开关，默认关闭；
- 代码: 新后端文件独立，删除 feature 不影响现有 `mpv-poster`。

## 8. 待决问题

- libmpv 构建是 GPLv2+ 还是 LGPL？桌面分发姿态？
- 是否接受 app 进程内解析不可信媒体？是否需要独立 helper 进程？
- HTTPS 自签证书继续 `--tls-verify=no`，还是做 localhost 代理以保留 pin？
- 桌面海报并发从 11 降到多少？
- 是否需要在 Android 上替换 media_kit screenshot？

## 9. 启动命令

```powershell
# 当前特性门禁（不启用新后端时）
cargo test -p rcrm-flutter-bridge --features mpv-poster
cargo clippy -p rcrm-flutter-bridge --features mpv-poster --all-targets

# 未来新特性（实现后）
cargo test -p rcrm-flutter-bridge --features libmpv-poster
cargo clippy -p rcrm-flutter-bridge --features libmpv-poster --all-targets
```

原型脚本（本机 gitignored）: `.local_backup/mpv_bench.py`、`.local_backup/mpv_compare_frames.py`。

## 10. 启动清单

- [ ] 法务/许可证结论（未做；libmpv 仍按 media_kit 既有姿态随包分发）
- [x] 确认 Windows libmpv 加载路径（`libmpv-2.dll`，与 media_kit 同一个文件，实测）
- [x] 新增 `libmpv-poster` feature 与 `libloading`
- [x] 实现 context + SW render + 正确的 update/seek 协议（含 seek 前消费旧帧、
  `time-pos` 校验、每阶段超时）
- [x] 实现 BGRA 原地编码 + alpha/blank 一次遍历（`encode_poster_frame`）
- [x] 接入 `ThumbnailService`（按后端，不按平台）并删除 ffmpeg 回落
- [x] 日志：`POSTER|libmpv|…` 与 Rust 侧 `[poster] libmpv … loaded_ms/seek_ms/frame_ms/encode_ms`
- [ ] 真实网络/4K/并发基准（只做了一次本地 720×960 单路实测）
- [x] 更新 CHANGELOG、API_REFERENCE、BUILDING、ARCHITECTURE、PRODUCT、AGENTS
