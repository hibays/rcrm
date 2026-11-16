# Rust review：libmpv 海报（第二版）

日期: 2026-11-16（第二版；同日第一版被本文件取代）
第三轮复核（同日 09:35，首候选 REDRAW 帧错位）见第 7 节。
范围（只有 mpv 相关）: `crates/rcrm-flutter-bridge/src/{libmpv.rs,libmpv_poster.rs,poster.rs,webp.rs,lib.rs}`
的 libmpv 路径，以及它的两个 Dart 后端 `services/{poster_libmpv,poster_mpv}.dart` 与
`services/thumbnail_service.dart` 里的排队/暂停部分。

## 0. 结论

上一版把三处“看起来像 bug”的地方按 Must-fix 修了。逐条复核后**三处都不是可复现的
bug，已全部撤回**。现在留在工作区的行为改动只有一项：**被 libmpv 拒绝的选项改用 error
级日志**（mpv 升级时的唯一线索）。其余是解释性注释与一条不变量声明。

复核手段：读实现（含 media_kit_video 2.0.1 源码）、追调用链与参数来源、算可达性。
`cargo miri` 在本机不可用（stable-msvc 无该组件），且 Miri 对 `extern` 调用不透明，
凡涉及别名模型的判断只给出推导依据，不声称“跑过”。

## 1. 逐条复核

| # | 上一版结论 | 复核依据 | 实际结论 | 处置 |
|---|---|---|---|---|
| 1 | `Surface::pointer` 从 `&self` 派生 `*mut` 是 UB | 见 1.1 | **不是 UB** | 撤回，留解释性注释 |
| 2 | `Surface::new` 乘法回绕 → 堆越界 | `generate → target_size → Surface::new` 是唯一链；width ≤ 640、height ≤ 8192 → 21 MB | **不可达** | 撤回，留 `debug_assert` 不变量 |
| 3 | `render` 的 `u32 as c_int` 可能翻负 | 同一约束 | **不可达** | 撤回 |
| 4 | 空 `positions` 会白建 client | Dart `posterSeekPlan` 两个分支都至少返回一个元素 | **不可达** | 撤回 |
| 5 | Dart 海报池可能“有 player 无 controller” | `media_kit_video-2.0.1/…/video_controller.dart:72` 构造器同步、不抛；异步失败走 `:124` 的 `completeError`，消费它的 `:160` 我们已 try/catch | **不会发生** | 撤回 |
| 6 | client API 加 major 上限 | 当前 libmpv 全是 2.x，永不触发；锁 major 会挡住未来版本 | **没必要** | **已按你的意见删除** |

### 1.1 为什么 `Surface::pointer(&self)` 不是 UB

`Vec::as_ptr` 返回的是 `Vec` **内部存着的 buffer 指针**（`self.buf.ptr()`），它不经过
`&[u8]` 切片、也不对堆分配重新打 tag；`&self` 只冻结 `Surface`/`Vec` **结构体自身的
字节**（那个指针值），不冻结它指向的堆分配。libmpv 写的时候，全流程没有任何指向该分配的
`&[u8]` 存活。所以这是“通过结构体里保存的裸指针做内部可变性”，是 FFI 的常规形态。

反例是另一种写法：如果指针来自 `&self.storage[..].as_ptr()`（先造 slice 引用），那才是
从共享引用派生的只读来源，写它就是 UB。代码里没有。

上一版还说过“miri 会红”——这一点也是错的：这次写发生在 libmpv 内部，Miri 对 `extern`
调用不透明，看不到这次写。签名已恢复 `&self`，并留注释说明为什么成立、换成 slice 派生
就不成立（防止下一个人重复这次误判）。

### 1.2 为什么 `Surface::new` 的乘法不可达

`target_size`（`libmpv_poster.rs`）里 `width = max_width.max(1).min(source_width)`，
`max_width` 来自 Dart 常量 `posterWidth = 640`；`height` 被 `clamp(1, MAX_HEIGHT = 8192)`
截断。于是 `len = 640 × 8192 × 4 ≈ 21 MB`：64 位不可能溢出，32 位（armv7）也远低于
`usize::MAX`。改回直接算术，用一条 `debug_assert!` + 注释把这个不变量写在构造函数旁
（release 零成本），不是守卫。

## 2. 现在留在工作区的改动

1. **`libmpv.rs`：被拒选项的日志级别 `log_debug! → log_error!`。**
   mpv 升级最常见的破坏形态是选项改名（`tls-verify`、`http-header-fields`、`keep-open` …），
   而 `mpv_set_option_string` 只返回错误码。这一行是升级后唯一的线索，默认级别可见才叫线索。
2. **注释与不变量**（无行为变化）：`Surface::pointer` 为什么 `&self` 成立；
   `Surface::new` 的尺寸契约 + `debug_assert`；`render` 的 `int[2]` 说明。

## 3. libmpv 海报的并发与异步现状

| 项 | 移动端 | 桌面 | 出处 |
|---|---|---|---|
| 同时生成的海报 | **1** | 4 | `ItemCacheLimit.videoPosterConcurrency` |
| 排队上限 | **24** | **128** | `videoPosterQueueMax`（本版从 50/200 下调；保持在内存 LRU 之下） |
| 内存 LRU | 32 | 512 | `videoPosterMemoryCacheMax` |
| mpv 实例 | Android：每个 job 一个 context，建完即销毁（峰值 1）；iOS：复用池 1 个 Player | 同 Android，峰值 ≤ 4 | `libmpv_poster::generate` / `MpvPoster._ensurePool` |

排队上限为什么必须小于 LRU：被淘汰的等待者会被回答 `null` 且**不会重试**，所以队列比它
喂的那层缓存还深，就等于把槽位花在“结果根本放不下”的请求上。

实测（720×960 竖屏，release）：`load 23–32 ms + seek ≈0 + frame 47–59 + encode 63 ≈ 140 ms/张`。
移动端串行 ≈ 7 张/秒；一屏 20 张约 3 秒，而且是滚动中增量请求。移动端没有跨 job 的
mpv 复用（每张约 25 ms 创建 + 一次线程启动）。

异步模型（只有海报这条链）：

```
VideoPoster.initState → postFrame → ThumbnailService.generatePoster(url)
  ├─ 内存 LRU 命中 → 立即 Future.value
  ├─ ThumbCache 命中 → await 读盘
  ├─ _posterInflight 命中 → 复用同一个 Completer（同 URL 只跑一次）
  └─ 入队 PosterJob（FIFO，上限 24/128，超出淘汰最老等待者 → null）
       → _posterKick: 并发 ≤ 1/4，且未暂停、无 parked job
       → run(): 主 isolate 上的 async 函数
            ├─ libmpv 后端（Android/桌面）：
            │    rcrm_generate_poster_async → Rust std::thread::spawn
            │      → mpv create/loadfile/seek/render/encode
            │      → callback（NativeCallable.listener，回主 isolate 事件循环）
            │    Dart 只 await 一个 Completer，主 isolate 不阻塞，帧不进 Dart
            └─ media_kit 后端（iOS）：
                  池里 1 个 Player.screenshot（原生回调经 media_kit 的 port 回来）
                  seek 完成用 stream.position 的 Future 等，不忙轮询
                  暂停闸门：park → stop → await resume → re-open → unpark
  ← 完成后写内存 LRU + await ThumbCache.write → complete
```

要点：**没有取消机制**（已开始的 job 跑完才回答，排队中的可被淘汰）；**暂停时**队列停止启动，
iOS 的跑中 job 会 park，libmpv 的 job 无法 park（无共享锁）但会跑完；**超时**是 Dart 60 s
兜底 / Rust 40 s 总预算（load 25 s、seek 5 s、frame 3 s 分阶段），正常情况答案总在 Dart
超时前到达，晚到的 Rust 回调自己释放 buffer。

## 4. ffmpeg 9 / mpv 升级前瞻

先给结论：**先坏的会是“播放”，不是海报**。

1. **海报路径**已显式 `tls-verify=no`（`libmpv_poster::options()`）。ffmpeg 9 把
   `tls_verify` 默认值翻成 1 不影响显式设置；风险是 ffmpeg 9 **改名/移除该键**——那时 mpv 仍
   接受 `--tls-verify`（它自己的选项），ffmpeg 忽略未知字典键 → 海报静默变空。升级后对自签
   HTTPS 服务器跑一次 `RCRM_MPV_POSTER_TEST_VIDEO`；兜底顺序：局部 relay →
   `--tls-ca-file` 文件型证书 → `--stream-lavf-o` 传 pin。
2. **播放路径没有任何 tls 选项**（全仓库 grep 只有 `httpHeaders`）：`video_player_screen`、
   `preview_player`、`live_photo`、cast receiver 都是 media_kit 直接开 URL，ffmpeg 9 之后
   自签 HTTPS 的云端模式会**播不动**。现成机制是 `NativePlayer.setProperty('tls-verify','no')`
   （`_resumeAfterTakeBack` 已用该通道），在 `open` 前设置；这等于放弃播放路径的证书校验
   （Dart HTTP 仍 pin），属产品/安全决定，本次只记录。
3. **选项语义/改名**：升级后第一件事 grep `[poster] libmpv rejected option`（第 2 节第 1 项）。
4. **client API 版本**：只保留下限 `REQUIRED_API = 1.28`（render API 自该版本起）。不再锁
   major；下一个 major 会重排 enum 数值、默认禁用事件（`client.h` 的 "Future changes"），
   升级时按 `render.h`/`client.h` 复核一遍事件号与参数号即可。soname 若变成 `libmpv.so.3`，
   需要扩充 `library_names()`。
5. **色彩管线**：`bgr0` 是 ffmpeg 核心格式，风险低；HDR→SDR tone map 默认值变化会让海报
   观感变化，用 MAD/截图对比回归。
6. **SW 渲染性能**：render.h 明说 stride/pointer 不按 64 对齐会退化为整帧拷贝；我们满足，
   升级后若 `frame_ms` 突然变大先查这里。
7. **时序**：“render context 必须在 `loadfile` 前创建”是文档承诺；升级后若出现黑帧/首帧
   错位先复核这一条。
8. **卡死上界**：mpv 默认 `network-timeout=60s`，`loadfile`/`terminate_destroy` 是阻塞调用，
   我们的阶段超时只在阶段之间生效。Dart 超时率变高时先调小 mpv 的 network-timeout。

## 5. 验证

- `cargo fmt --check` 通过；`clippy --all-targets` 在 `libmpv-poster` 与 `mpv-poster`
  两种形态下零 warning；`cargo test -p rcrm-flutter-bridge --features libmpv-poster`
  39 例全绿。
- 真机端到端（720×960）：`load → seek → frame → encode → 640×853 不透明 WebP` 通过
  （debug 下 encode 约 2–3 s 是 debug 编码器；release 实测 63 ms）。
- `flutter analyze lib test`：No issues；`flutter test` 全绿（本次只改了 `videoPosterQueueMax`
  的数值与注释）。

## 6. 未验证

- `cargo miri` 不可用（无 nightly 组件），且 FFI 写对 Miri 不透明，别名模型只有推导依据。
- 未在 Linux/macOS/Android 真机跑真实 libmpv（库发现与 SW 渲染只在 Windows 验过）。
- 4K/HEVC/长 GOP、多路并发下的内存与吞吐未测；`videoPosterConcurrency = 4` 取的是评估
  报告的建议值，不是实测最优。
- 新的排队上限 24/128 只是常量调整，没有压测数据背书；它约束的是“等待中的请求”，
  不改变单张成本。

## 7. 第三轮复核（2026-11-16 09:35）：空帧重试不会重开 mpv；首候选帧错位

### 7.1 问题

“空帧（blank test 判空）时，同一个文件能否在同一个 mpv 实例里换位置取帧、不再付
20–30 ms 的启动成本？所以最坏情况也远好于旧 ffmpeg 路径？”

### 7.2 结论：是，两个后端都是一次 job 一个实例

- **libmpv**（`libmpv-poster`）：`libmpv_poster::generate` 每个 job 只
  `Mpv::create` + `RenderContext::new` 一次；Dart 把整个 `posterSeekPlan` 作为
  一个 `positions` 字符串下发，Rust 在同一个 client 上逐位置 `seek`，空帧
  （`PosterResult::Blank`）只是 `attempt` 返回 `Ok(None)`，循环继续下一个位置。
  `LibMpvPoster.generate` 一个 URL 只调用一次，所以 20–30 ms 的 client 创建是
  **每文件一次**，不是每候选位置一次。
- **media_kit**（iOS / 回退）：`MpvPoster.generate` 一个 job `open` 一次，空帧
  `break` 出重试循环后 `continue` 到下一个位置，仍在池里同一个 `Player` 上 seek；
  `open` 只在换文件/换 job 时发生。

实测（本机，release，1080p 纯黑样本，6 个候选全部判空）：一次 job 537 ms（含
`load`）；同一文件、同一组位置，旧 ffmpeg 路径为 1.3–5.6 s——它每个位置还要试
input-seek 与 output-seek 两种模式，每次一个进程。空帧判定在编码之前
（`encode_poster_frame` 先 luma 再 `encode_bgra`），所以空候选只付 seek + render +
luma，不付 WebP 编码；最坏情况确实是 libmpv 优势最大的地方。

### 7.3 复核中发现并修复的真实 bug：首候选渲染的是 seek 之前的帧

**证据**（2730×1440 样本，位置 3.5 s，单位置 job）：

- 第一个 post-seek 帧 `frame_info` = `PRESENT | REDRAW`（flags=3），
  渲染结果 luma = **0.00**；ffmpeg 同位置 = 32.19。
- 同一次 job 的第二个位置（5 s）flags=1，luma 33.92，与 ffmpeg 一致。
- 1080p、黑开头的电影在第一候选 30 s 也复现：luma 0.00（被误判为空帧），
  ffmpeg 同位置 69.75。开头的首帧若是正常画面而不是黑色，则会被 `time-pos`
  接受为“这个位置的帧”——即海报位置错位，而不只是空帧。

**根因有两层**：

1. `loadfile` 返回只代表头部读完，首帧稍后才解码；如果第一次 `seek` 赶在这之前，
   首帧会在 seek 之后才到，而 `time-pos` 已经移到目标，`POSITION_TOLERANCE`
   检查通过。
2. seek 期间 renderer 会先发一个 **REDRAW/REPEAT** 更新（render.h 的
   `MPV_RENDER_FRAME_INFO_REDRAW` / `_REPEAT`，两者都蕴含 `PRESENT`）：它复现的是
   **上一张**画面，不是 seek 的目标帧；`time-pos` 同样已经到位，所以时钟校验拦不住。
   `drain()` 只能在 seek 前消费“已经存在”的帧，拦不住 seek 之后才发来的 redraw。

**修复**（`libmpv_poster.rs` / `libmpv.rs`）：

1. `wait_for_first_frame`：`wait_for_load` 之后、第一次 seek 之前，等
   `mpv_render_context_update` 报出首帧（2 s 上限；文件始终不出帧就交给后面的
   `attempt` 报错）。随后 `attempt` 的 `drain` 把它消费掉，第一次 seek 不再和首帧
   抢跑。
2. `RenderContext::frame_info`（`MPV_RENDER_PARAM_NEXT_FRAME_INFO`）+
   `is_previous_frame`：`PRESENT` 且带 `REDRAW`/`REPEAT` 的帧画出但**永不认账**，
   继续等真正的帧；到 deadline 仍没有真帧就按“这个位置失败”处理，交给下一个候选。
   宁可这个位置没有海报，也不把别的位位置的文件当成这一张——media_kit 后端早就是
   这条规则（stale 帧只重拍、不入档）。

**一个 ABI 陷阱（差点留下跨平台隐患）**：`mpv_render_context_get_info(ctx,
mpv_render_param param)` 的参数是**按值**传的结构体，不是数组。最初按
`(*mut RenderParam)` 绑定，Windows x64 的 16 字节结构体恰好也是按隐藏指针传参，
所以本机“能用”；但 SysV（Linux/macOS）与 AArch64 会把它拆进两个寄存器，读到的是
垃圾。已改为 `extern "C" fn(*mut MpvRenderContext, RenderParam) -> c_int`，与
`render.h`/docs.rs 的签名一致。

### 7.4 验证

- 样本矩阵（单位置、首候选）：720×960 luma 58.56（encode 通过）、1280×720
  luma 181.39、1920×1080 黑开头 3 s luma 24.06（旧代码是 0.00）、2730×1440
  3 s 触发 redraw 后 frame_ms 273–278 ms（4 线程时 437–464 ms）、encode 32–34 ms。
- 内容正确性：2730×1440 位置 3.5 s 的海报与 ffmpeg 同位置 MAD = 3.58（WebP 有损 +
  缩放差异），与 5 s 的 MAD = 28.64（不是同一帧）。
- 空帧语义未变：纯黑 1080p 的 6 个候选仍全部判 blank，阈值不变；删除 skip 后四种样本复测仍全部出图。
- 门禁：`cargo fmt` / `clippy --features libmpv-poster --all-targets -D warnings` 干净；
  `cargo test` 三种形态 40 / 34 / 25 例全绿，新增 `a_redraw_is_not_the_seeks_frame`；
  端到端用例改成**单位置**（正是出问题的首候选）。

### 7.5 `SKIP_RENDERING` 的复核：没有收益，已删除

`drain()` 曾用 `MPV_RENDER_PARAM_SKIP_RENDERING` 只消费不画。本轮把两种方式各测一遍
（本机 release，同一 720×960 样本）：

| drain 方式 | drain 耗时 | 紧跟的目标帧 | 合计 |
|---|---:|---:|---:|
| skip | 0.14 ms | 77 ms | 77.1 ms |
| render | 19.4 ms | 58 ms | 77.4 ms |

SW 渲染器的首帧有一次**一次性预热**（色彩转换 + scaler 初始化，约 19 ms @ 640×853）；
skip 只是把它推到下一帧，**总时间不变**。而 skip 还要依赖一个旧 libmpv 未必实现的
render.h 参数（版本检查只到 1.28）。所以 `RenderContext::skip` 与
`PARAM_SKIP_RENDERING` 已删除，`drain()` 回到 `render + report_swap` 的文档协议。

### 7.6 解码线程：4 → min(核数, 8)

`absolute+exact` 的 seek 本质是“从关键帧解码到目标”，所以解码线程数直接决定海报耗时。
本机（10 核 / 16 线程）同一 3 s 首候选实测：

| 样本 | 4 线程 | 8 线程 | 16 线程（mpv auto） |
|---|---:|---:|---:|
| 2730×1440 | 437–464 ms | 264–271 ms | 197–198 ms |
| 1920×1080 | 74–78 ms | 53–59 ms | — |
| 1280×720 | 47 ms | 35 ms | — |
| 720×960 竖屏 | ~76 ms | ~21 ms | — |

所以 `vd-lavc-threads` 从写死的 4 改成 `decoder_threads()`：`min(核数, 8)`（Android
上限 4）。8 线程拿到大部分收益，同时把 libavcodec 的帧缓冲（每线程一份 + DPB）压在
桌面可接受的范围；手机上 4K 10 bit 按 4 线程封顶，避免一张海报就占 ~96 MB 帧缓冲。

### 7.7 明确没有做的事

- **跨 job 复用 mpv client**：每个 job 仍创建一次（约 20–30 ms）。跨 job 池化需要
  “一线程一 client”的 render context 亲和性，并常驻 4 MiB demux 缓存/解码器缓冲；
  换文件本来也要 `loadfile`。同文件重复请求已被 in-flight 去重 + 内存/磁盘缓存
  挡住（只有 `refresh` 或空结果后的重新挂载会再来一次）。
- **空结果负缓存**：`generatePoster` 只缓存成功结果；一个永远出不了海报的文件在
  卡片重新挂载时会重跑一次 job（旧 ffmpeg 路径同样如此，且更贵）。是否接受
  “会话内负缓存”是产品取舍，本轮不动。
