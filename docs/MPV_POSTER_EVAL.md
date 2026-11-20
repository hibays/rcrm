# MPV libmpv 原生海报生成评估报告

日期: 2026-11-15
状态: 可行性原型完成，未接入生产代码（当时的状态；现已实施并接入生产代码，见文首横幅）
后续执行计划: `docs/PLAN_MPV_POSTER.md`

> **⚠️ 全文为历史文档（已被后续实现取代）**：本文是 2026-11-15 的可行性评估。结论已落地，但方案已被改写 —— libmpv 海报后端现已是**唯一**后端（所有平台，含 iOS），ffmpeg CLI 与 media_kit 截图后端均已删除。文中"保留 ffmpeg 回落""iOS 不建议""当前生产路径是 media_kit screenshot"等均为当时的判断，不再反映当前代码；现状请以 `docs/MPV_POSTER_REVIEW.md`、`docs/ARCHITECTURE.md` 与 `AGENTS.md` 为准。下文标有"当时的状态"的行保留原貌，仅作历史记录。

> **2026-11-16 追加**：iOS 也已走 libmpv 路径（media_kit 的 `Mpv.framework/Mpv` 是动态、已签名的 `MH_DYLIB`），`mpv-poster` 与 media_kit 截图后端已删除。本文中"iOS 不建议"的结论是当时的历史判断，已被取代。

## 1. 结论

**技术上可行，性能有明确收益，但现在还不能直接、无条件替换桌面端 ffmpeg CLI。**（当时的判断；现已直接替换，ffmpeg CLI 后端已删除）

原型在当前 Windows 机器上用 libmpv 0.36 的 `MPV_RENDER_API_TYPE_SW` 软件渲染，把帧直接写进 Rust 分配的 native 缓冲区，再把同一指针交给 Rust 的 WebP 编码器。帧数据没有经过 Dart，也没有中间拷贝；与 ffmpeg 抽帧的像素对比 MAD 约 2.4-3.6（WebP 有损 + 缩放差异）。

【当时的建议（现已实施为唯一后端，ffmpeg 回落与 `mpv-poster` 均已删除）】建议以独立特性 `libmpv-poster` 做可选后端，保留 ffmpeg 回落；先在 Windows 上 A/B，再评估 Linux/macOS 和 Android。不要复用现有 `mpv-poster`（后者是 media_kit screenshot + Rust 编码，不是 libmpv render API）。

## 2. 原型链路

```text
Rust: libloading -> libmpv-2.dll (mpv_create / mpv_initialize)
      -> mpv_render_context_create(MPV_RENDER_API_TYPE_SW)
      -> mpv_command seek
      -> mpv_render_context_update (FRAME flag)
      -> mpv_render_context_render -> Rust native buffer (bgr0)
      -> blank test + WebP encode (same buffer, no Dart copy)
      -> WebpBuf returned to Dart as a zero-copy view
```

【当时的状态（现已被 libmpv 唯一后端取代）】当前生产移动端路径是 media_kit `screenshot-raw` -> Dart `Uint8List`（`sublist(0)` 一次 copy）-> `ThumbWebpWorker` 再 copy 到 native -> Rust blank/resize/WebP。libmpv 原生路径可以省掉这两次全帧 copy。桌面 ffmpeg 路径没有原始帧进 Dart，但有进程启动和 JPEG 编码成本。

## 3. 实测环境与方法

- 主机: 当前 Windows 开发机
- libmpv: 0.36.0 (media_kit 自带的 `libmpv-2.dll`)
- ffmpeg: 9.0.2 (MSYS2 ucrt64)
- Rust bridge: release 构建，启用 `mpv-poster`
- 方法: libmpv 一次 load，多个位置 warm 帧；每点 5 轮取中位数；ffmpeg 每点独立进程，参数与桌面海报一致（`-ss` 输入 seek、`-vframes 1 -q:v 3 -vf scale=640:-1`、JPEG 到 stdout）
- 帧正确性: 保存 libmpv WebP 与 ffmpeg JPEG，Pillow 转 RGB 后计算平均绝对差 MAD
- 注意: 本地文件、OS 缓存已热、单路；未测真实 WebDAV HTTPS、4K/HEVC、并发和内存峰值

## 4. 性能数据

### 4.1 1280x720, 107.9s, 23 MB, 目标 640x360

| 位置 | libmpv seek | render | Rust encode | libmpv 总计 | ffmpeg CLI |
|---:|---:|---:|---:|---:|---:|
| 3s | 38.8 ms | 0.47 ms | 37.6 ms | **77.8 ms** | 147.8 ms |
| 15s | 47.8 ms | 0.54 ms | 39.7 ms | **87.9 ms** | 149.9 ms |
| 30s | 10.4 ms | 0.40 ms | 37.4 ms | **48.5 ms** | 121.2 ms |
| 60s | 10.5 ms | 0.55 ms | 34.7 ms | **46.7 ms** | 110.6 ms |

冷启动 `mpv_create -> loadfile -> FILE_LOADED` 约 25 ms；第一帧冷总计约 103 ms，仍略快于 ffmpeg 的 148 ms。

### 4.2 720x960 竖屏, 10.0s, 目标 640x853（按比例）

| 位置 | libmpv 总计 | ffmpeg CLI |
|---:|---:|---:|
| 1s | **94.2 ms** | 136.3 ms |
| 3s | **106.1 ms** | 148.9 ms |
| 5s | **116.3 ms** | 158.1 ms |
| 7s | **127.9 ms** | 161.5 ms |

竖屏高帧面积下 encode 上升到 79-83 ms，优势收窄到约 1.2-1.5 倍。

### 4.3 汇总

- 16:9 warm 帧: 约 1.6-2.4 倍快于 ffmpeg
- 竖屏/高面积 warm 帧: 约 1.2-1.5 倍快
- 第一帧冷启动: 约 1.1-1.4 倍快
- 成本结构: seek 10-48 ms, render 0.4-0.7 ms, Rust WebP encode 35-83 ms；ffmpeg 的进程启动 + JPEG 编码是主要成本

## 5. 帧正确性

正确实现 seek -> 事件 -> render 的更新顺序后，1280x720 样本在 3s/30s/60s 与 ffmpeg 的 MAD 为 2.35/2.39/3.57。

错误实现（不消费上一帧的 update flag）会渲染旧帧：同位置 MAD 达到 74.35/7.66/83.56，60s 实际渲染出 3s 的画面。**不能只等待 `MPV_EVENT_PLAYBACK_RESTART`，也不能直接轮询 update 而不先消费旧帧。**

## 6. 必须处理的坑

1. **先消费旧帧**: seek 前 drain events，调用 `mpv_render_context_update`，若返回 `MPV_RENDER_UPDATE_FRAME`，先 render + `report_swap`。
2. **等待 SEEK 事件 (20)，再轮询 update**；不要等 `PLAYBACK_RESTART` 再 render，实测稳定慢约 220 ms。
3. **按视频宽高算目标高度**: `target_h = round(640 * h / w)`；否则 `SW_SIZE` 会 letterbox，竖屏海报出现大黑边。
4. **alpha**: `bgr0` 的 alpha 字节是 0；编码前要原地写 255，或用不透明 BGRA 编码路径。
5. **命令行**: 原型中 ctypes 的 `mpv_command` argv 在跨 bridge 调用后不稳定；`mpv_command_string` 正常。Rust 应使用自己持有的 `CString`，不要依赖调用方临时字符串。
6. **SW render 是 CPU 单线程**，libmpv 文档明确说它“非常慢，不适合抽帧”；当前优势来自省掉进程和 JPEG。并发、4K、长 GOP 下必须重新测。

## 7. 零拷贝边界

已证明: mpv 写 Rust native buffer，Rust 直接读同一指针编码，帧数据不进 Dart。

尚未做到严格零拷贝: 当前 `poster::encode_poster` 仍会分配并做一次 BGRA -> RGBA 的转换/缩放。要达到严格零拷贝，应:

1. mpv 直接按最终目标尺寸渲染；
2. 使用 zenwebp `PixelLayout::Bgra8` 原地编码；
3. 在 alpha=255 的原地遍历里顺便做 blank/luma。

## 8. 替换桌面 ffmpeg 的评估

### 可行平台

- **Windows**: 最可行。`libmpv-2.dll` 已随 media_kit 在 runner 中，Rust `libloading` 可直接加载。
- **Linux/macOS**: 可行，需要定位 `libmpv.so.2` / `libmpv.dylib`，处理缺失回落。
- **Android**: 大概率可行，`libmpv.so` 已在 jniLibs；需要验证 linker namespace 和符号可见性。
- **iOS**: 不建议。media_kit 的 libmpv 是静态链接，iOS 不允许任意 `dlopen`；Rust 再静态链接一份会引入符号冲突和 Xcode 构建复杂度。

### 收益

- 桌面不再依赖 PATH 上的 ffmpeg；
- 没有每帧 `CreateProcess`；
- 一个 libmpv context 可跨多个候选位置复用；
- 帧到 WebP 可做到 native 零拷贝；
- 与现有 Rust blank/resize/WebP 能力天然衔接。

### 风险

1. **进程内崩溃隔离**: ffmpeg 是独立进程，坏文件最多子进程失败；libmpv 段错误会杀 app。media_kit 播放已经承担该风险，但海报生成会增加一次解析。
2. **许可证**: libmpv 默认 GPLv2+（除非 LGPL 构建）；ffmpeg CLI 独立进程与链接 libmpv 的法律姿态不同，需要法务确认。
3. **TLS 钉扎**: libmpv 自签证书需要 `--tls-verify=no`，与 ffmpeg 的 `-tls_verify 0` 一样绕开 Dart pin；若要继续 pin，需要 localhost 代理或 CA 方案。
4. **并发/内存**: 11 个 ffmpeg 进程换成 11 个 libmpv context 可能内存和 CPU 都吃不消；建议 2-4 个 worker 起测。
5. **构建/平台**: `libloading`、库发现、版本兼容（`mpv_client_api_version`）和 iOS 排除都要工程化。
6. **不是全面碾压**: 竖屏/高面积仅快 1.2-1.5 倍，冷启动仅 1.1-1.4 倍；真正收益在 warm 多位置和去掉 ffmpeg 依赖。

## 9. 最终判断

【当时的判断（现已删除 ffmpeg，`libmpv-poster` 为唯一后端）】**值得做可选后端，但不建议现在删除 ffmpeg。** 先实现 `libmpv-poster`，保留 ffmpeg 回落，在真实 WebDAV/HTTPS、4K/HEVC、4-8 路并发下复测；只有稳定快 1.3 倍以上、内存可接受、许可通过，才考虑把桌面默认切到 libmpv。

原型脚本（gitignored，本机）: `.local_backup/mpv_bench.py`、`.local_backup/mpv_compare_frames.py`、`.local_backup/frames/`。
