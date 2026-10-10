# Update report

1. 2022.5.14.10.15.PM.Saturday
	1) 更新默认calibration_amount值为1024→896
	2) 这可能使解密以calibration_amount=1024加密的文件时虽提示成功但实际内容错误致最终酿成无以挽回的损失
	3) 也可能提示解密错误...

2. 2022.5.15.0.15.AM.Sunday
	1) 增加解码检查, 解出来无 b'ftyp' 的话报错

3. 2022.5.21.7.5.PM.Saturday
	1) 报错不再打印directory
	2) 对架构稍作更改

4. 2022.6.3.3.1.PM.Friday
	1) 稍对MOVe/dncode进行优化, 不再设置dat变量等
	2) 增加 xor_ctx.useascii 的setter, 设为False可将加密后数据缩减约18.2%
	3) 添加不可加密时报错

5. 2022.6.5.6.17.AM.Sunday
	1) 修复解码报错问题

6. 2022.7.4.8.39.PM.Monday
	*以下更新不向下兼容* 旧算法请见 `_od_MOVencode`, `_od_MOVdecode`, `_od_main`
	1) 更新编码机制
		① 将密码hash值嵌入文件末尾，增加活动性
		② 将calibration_amount嵌入文件末尾，增加稳固性
	2) 基于以上机制，解码时进行key检查，不通过则报KeyError
	3) 基于以上机制，解码后数据无 b'ftyp' 不再报错
	4) 设MOVencode的calibration_amount参数默认值为1024，MOVdecode不再提供该参数
	5) 更新main函数，增加多用性
	6) 将 xor_ctx.useascii 的值默认设为 False

7. 2022.8.3.12.32.PM.Wednesday
	*以下更新不向下兼容* 旧算法请见 `_od2_MOVencode`, `_od2_MOVdecode`, `_od2_main`
	1) 更改密码算法，增强安全性
	2) 加密核心改用RC4^+加密算法
	3) 稍微优化交互逻辑
	4) 考虑多平台下差异性, 加入Windows适配
		① 文件名ASCII算法从base85改为base58
	5) 将文件名保护嵌入密码算法中, 默认开启
		① 新增参 name_crypt 控制
		② 返回加密后文件名, 未加密返回原名
		③ 文件将更名为其哈希值
	6) 添加复加密验证，若同文件被同一参数加密多次则报 RuntimeError

8. 2022.8.5.11.26.PM.Friday
	1) 优化部分函数的实现

9. 2022.8.20.3.30.PM.Saturday
	1) 在所有版本添加对图片文件的支持

10. 2022.12.3.11.5.PM.Saturday
	1) 将 main 函数 dir 参数的默认值从 `path.dirname(path.dirname(__file__))` 改为 `path.abspath('..')` 以修复 `__file__` 在3.8或pypy中不是绝对路径导致的错误
	2) 添加了人性化的 Seeking Path 提示

11. 2.2023.1.25.9.45.AM.Wednesday
	1) 使用自带mimetypes得到更广泛的类型判断(audio,image,video)
		- note: 对历史版本生效
		- detail: rename SUPPORTFILES to _SUPPORTFILES
		
12. 2023.6.10.0.39.AM.Saturday
	0) !!!完全取消了向前兼容性!!!
	1) 完全重建架构，不向下兼容。
	2) 基于新的存储格式，现在加解密的文件io更快
	3) 支持了全大小文件的加密处理(现在不会再报错)
	4) 使用Chacha20基于nonce的算法，每个文件现在有不同的特征量
	5) 扩充b58到b60使编码更紧凑
	6) calibration_amount 为 -1 时将加密整个文件

13. 2024.2.13
	0) 此版本不具有向前兼容性!!!
	1) 默认使用更快的argon2_cffi和更安全的参数
	2) 扩充b60到b72使编码更紧凑
	3) 设calibration_amount参数默认值为2048
	4) 分离模块到thirdmod文件夹

14. 2025.9.7.11.56.PM.Sunday
	0) 此版本不具有向前兼容性!!!
	1) 更新了base72编码算法及其字符表，修复Windows下以base72重命名时可能触发的错误及解码错误
	2) 添加了一个命令行参数用以指定扫描路径

15. 2025.10.9.6.13.PM.Thursday
	0) 微调字节操作实现以增加性能

16. 2025.11.10.2.30.AM.Monday
	0) 修改文件名加密逻辑，现在文件加密后使用加密名字生成hash cover; Inplace encrypt file_name_b (changelog)

---

Update report:

使用rust重写整个程序：

1. 2025.11.10.4.5.AM.Monday
	0) 完成了rust版本的重写
	1) 编写了一个简单的命令行接口
	2) 编写了一个简单的测试
	3) 在安全性方面做了一些改进
	4) 本版本不具有向PY兼容性!!!

2. 2026.7.23.11.50.PM.Thursday
	0) 此版本不具有向前兼容性!!!
	1) 将密钥存储从Zeroizing<[u8;32]>迁移到LockedKey<32>(mlock/VirtualLock页面锁定内存, 防swap和coredump)
	2) SessionKey::generate()现在返回io::Result(mlock可能失败)
	3) 将base72编译期常量从lazy_static!改为const fn(利用Rust 2024 const-eval)
	4) 添加log_level模块, 实现运行时可配置的日志级别(log_info!/log_error!/log_debug!)
	5) 服务器TLS加密从ring provider切换到aws-lc-rs
	6) 更新rcgen 0.13→0.14, rand 0.9→0.10
	7) 在release profile中启用codegen-units=1(最大化单函数优化)
	8) 将默认最大连接数从16提升到32
	9) 改进WebDAV dispatch错误处理(返回500而不是panic)
	10) 在WebDAV content-type映射中添加avif格式支持

3. 2026.10.7.10.40.PM.Wednesday
	*本批为未发布的工作区改动汇总*

	1) 查看器重做
		① 缩放/平移改为只变换照片本身(不再缩放信箱边距)，任何缩放与位移都不会露出空白
		② 双指/滚轮以焦点为中心缩放，双击缩放至点击处(2.5×)或复位，最大 6× fit；1:1 上限 6× fit
		③ 下拉关闭：位移 1:1、横向阻尼 0.35；阈值取视口 12%(72–132px 夹取)或 >700px/s 快速甩动
		④ 顶部 chrome 改为浮在照片上的圆形按钮 + 文件名/位置，胶片条改为底部渐隐 scrim
	2) 图片信息面板(EXIF / track)
		① Rust 侧新增 `rcrm_media_metadata_async`(nom-exif 纯内存解析，不落盘)，JSON → 不可变模型
		② 面板按画廊习惯排版：大日期 → 文件名 → 位置行 → 相机块 → 标签行；橙色只用在 1:1 chip
		③ 只在解析成功后才声明"没有相机/位置信息"；解析失败或未取得字节时保持沉默
		④ 失败结果不写入缓存(下次打开重试)，解析回调有 10s 超时兜底
		⑤ 修复 WebDAV `getlastmodified` 只按 ISO 解析导致的空日期：现在兼容 RFC 1123 并按本地时间显示
	3) 播放器 chrome 重写
		① 密度按窗口最短边分档(compact/regular/expanded)，全屏不再放大控件；底栏新增极窄档位(≥~108dp 不再溢出)
		② 宽度预算：时间 → 跳过 → 倍速 → 剧集，音量滑条取剩余空间，不足 64dp 时隐藏并由静音键承担
		③ 顶栏(返回/标题/设置齿轮)在所有平台一致；设置面板或倍速菜单打开时 chrome 永不自动隐藏
		④ 修复倍速 chip 预算与绘制字体不一致、滚轮音量不夹取、点击目标被 VisualDensity 缩小等问题
	4) 直播照片不再落盘
		① media_kit 的 `Media.memory` 会写临时文件且只在 GC 时删除；改为 `LiveMediaServer`：仅回环绑定 + 128bit token，从内存提供 mp4
		② 播放器销毁时释放载荷，交接期最多驻留两份
	5) 零拷贝传输(本轮重点)
		① 新增 `services/native_bytes.dart`：HTTP 响应直接写进 native 缓冲(按 Content-Length 精确分配)，FFI 交接不再复制
		② 图片软解输入：AVIF/JXL/HEIC 原图经 native 抓取直达 Rust，省掉整帧复制；查看器 RGBA→ui.Image 的一次复制仍是硬限制(dart:ui 只接受 Dart 缓冲)
		③ 缩略图：新增 `rcrm_generate_thumb_webp_from_image`(解码→缩放→WebP 一次完成，输入借用)，移动端 AVIF/JXL/HEIC 缩略图从 3 次整帧复制降到 0
		④ 元数据：交接带容量(`cap`)精确释放；`DecodeBuf` 增加 `cap` 字段以支持解码器直接交出 `Vec`
		⑤ 修复 worker 超时后主 isolate 提前 free 输入缓冲导致的 use-after-free(改由 worker 持有一份)
	6) HEIC/HEIF 支持
		① `mobile-decode` 增加 `heic`(git dep，纯 Rust HEVC `backend-rust` + `parallel`)，与 AVIF/JXL 同一开关，桌面仍不编译
		② 新增 `rcrm_decode_heic_async` 与缩略图 kind_hint=3；容器方向(irot/imir)与 clap 裁剪由解码器处理
		③ 缩略图缩放使用与 JXL 相同的双线性采样；解码上限取 64MP(HEIC 不能用 AVIF 那套 8.3MP —— 手机 HEIC 普遍 12–48MP，照搬会把真实照片全部拒掉)
		④ 修复 HEIC 一开始照搬 AVIF 的 8.3MP 上限导致的"桌面 heic 解码不出来"(16MP 的 iPhone 照片被 LimitExceeded 拒掉)，并去掉 `#[cfg(test)] u64::MAX` 逃逸(正是它让测试全绿而 App 无图)，补端到端缩略图回归测试
	7) 其它
		① `flutter analyze lib test` 与 `cargo clippy --all` 均零告警；Rust 单测 46(含 mobile-decode)、Dart 测试约 250
		② 文档全面更新：README/README_zh、ARCHITECTURE、API_REFERENCE、BUILDING(含 ffmpeg≥9 TLS 与 Flutter 3.47 Impeller 两个环境级已知问题)、DESIGN、AGENTS
		③ 暂存区只读审查后的修复：去掉 _v2(不需要版本化，导出即 rcrm_media_metadata_async)；getlastmodified 统一到 UTC 口径(ISO 无时区不再按本地时间解释，否则同一目录内排序会偏一个时区)；查看器下拉关闭与返回键的双重 pop 合并为单一守卫(此前会把查看器下面那一屏也弹掉)；信息面板在答复未到时不再先断言 No camera/location information(改骨架占位；骨架比它替代的那一块矮，因此答复到达时下方各行会有小幅位移——这是不撒谎的代价，原先"无跳动"的说法是错的)，EXIF 尺寸按 orientation 5-8 交换宽高，非整分数曝光时间不再写成 1/1 s；缩略图 Rust 快路径失败时只在"网络已给出终局答案"(请求被拒/空响应)才放弃，字节到手而 Rust 解码器拒绝的情形仍回落引擎解码(不同解码器，能读我们读不了的文件)——原先一律放弃会让查看器能显示的文件永远没有缩略图；元数据缓存淘汰不再驱逐在途项；worker 回复超时改为 kill 卡死的 isolate 并在其真正退出后回收输入缓冲；encodeRgba 全帧拷贝由两次降为一次(回退路径复用同一缓冲)
		④ 低优先项收尾：媒体元数据模型去掉裸 as(错类型字段不再让整份文档退化为 none)；播放器文本测量加缓存(按 文本+样式+缩放 记忆，上限 128)；控制栏在最窄宽度下继续降级(先让全屏、再让静音，播放键恒在)并修掉无条件 gap 导致的 2px 溢出，像素扫描下界从 120dp 降到 40dp；Rust 元数据导出的违约分支区分 no buffer/empty input/bad capacity 并按声明容量接管释放(不再两侧都不释放)；同步的缩略图导出加 catch_unwind(解码器 panic 不再跨 FFI abort)；鉴权头读取全部改为缺键即降级(5 处)；NativeFetch.retryWithCopy 真正被生产代码使用——分块响应(无法精确分配)回退到通用取字节路径，此前会直接丢掉缩略图；查看器下拉关闭改为只在 1x(fit) 生效——放大状态下拖拽只做平移，不再能从顶边把整屏拽掉(原先的 top-edge 判定已删除，连同只服务于它的 atTopEdge 通道与 ViewerZoom.atTopEdge)
		⑤ Windows 自绘标题栏拖动改为**鼠标发起**的移动：`rcrm/window` 通道 startWindowDrag → runner ReleaseCapture(); PostMessage(WM_NCLBUTTONDOWN, HTCAPTION, 0)（Electron/Tauri 同款）。原因：startDragging() 的 WM_SYSCOMMAND+SC_MOVE 被系统当作键盘移动，**Win11 会吸附、Win10 完全不吸附**；新做法两者都能吸附。fullscreen 时不拖（Dart isFullScreen() + runner WS_THICKFRAME 兜底）。曾试的子窗口 WM_NCHITTEST/HTTRANSPARENT 委托已放弃（与 fullscreen 冲突、会出现残影）。最大化时的客户区几何归 window_manager 的插件代理（TitleBarStyle.hidden 下它接管每个 WM_NCCALCSIZE），runner 里那个 case 已确认是死代码并删除
		⑥ open-code-review 只读审查后的修复：缩略图 worker 的输入缓冲改为**主 isolate 单一所有者**（worker 不再释放），按 isolate 归属登记、只在该 isolate 退出时或其回复到达时回收，`NativeBytes.reclaim()` 幂等——原来的两处会 use-after-free / double free；同批修掉被换代请求的缓冲泄漏、exit 事件不标记 worker 死亡（后续请求白等 15s）、spawn 失败泄漏 isolate 与两个 ReceivePort；AVIF 解码失败不再泄漏 dav1d context（RAII 必关）、`alloc_buf` 检查空指针、rav1d 的 frame_size_limit 从 0 改为接上限（容器 ispe 可伪造，此前是唯一闸门），AVIF 上限参数化并**删除 `#[cfg(test)] u64::MAX` 逃逸**（回归测试改为：生产入口必须接受 39MP 夹具、而低于文件体量的 ceiling 必须拒绝它），并把三个软件解码器的上限**统一为 64MP**（AVIF 原为 8.3MP，会拒掉所有 12MP 手机照片；JXL 与 HEIC 已是 64MP，另加 65536 边长与画布像素的 sanity 上限），三个 decode 导出与 metadata 同形改用 `Builder::spawn` + `catch_unwind`（线程创建失败不再 abort 进程、解码 panic 不再让 Dart 空等并占 gate 名额）；`window_drag` 通道不可用时仍回落到 startDragging（此前"回落前 return"会让旧 runner 只能拖一次）；AVIF 未处理 irot/imir 一事写成显式限制说明；文档修正：README 快速开始补 `--http`（原来起的是明文 FTP）、CHANGELOG 修复一个吃掉 `r` 的孤立 CR、DESIGN 补控制降级阶梯、ARCHITECTURE 修正 ⓘ 不在 AppBar、rust_bridge 所有权注释改为"取得所有权"
