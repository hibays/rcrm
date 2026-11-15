# PLAN: libmpv 原生海报生成（后续启动）

日期: 2026-11-15
前置报告: `docs/MPV_POSTER_EVAL.md`
状态: 方案待启动；当前生产仍使用 ffmpeg（桌面）/ media_kit + Rust（移动端）

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

- [ ] 法务/许可证结论
- [ ] 确认 Windows libmpv 加载路径
- [ ] 新增 `libmpv-poster` feature 与 `libloading`
- [ ] 实现 context + SW render + 正确的 update/seek 协议
- [ ] 实现 BGRA 原地编码 + alpha/blank 一次遍历
- [ ] 接入桌面 `_posterDesktop` 与 ffmpeg 回落
- [ ] 加 `POSTER|backend=libmpv` 日志
- [ ] 真实网络/4K/并发基准
- [ ] 更新 CHANGELOG、API_REFERENCE、BUILDING、AGENTS
