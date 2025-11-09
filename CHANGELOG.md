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
	4) 更新main函数，增加多用性
	5) 将 xor_ctx.useascii 的值默认设为 False

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

10. 2.2023.1.25.9.45.AM.Wednesday
	1) 使用自带mimetypes得到更广泛的类型判断(audio,image,video)
		- note: 对历史版本生效
		- detail: rename SUPPORTFILES to _SUPPORTFILES
		
11. 2023.6.10.0.39.AM.Saturday
	0) !!!完全取消了向前兼容性!!!
	1) 完全重建架构，不向下兼容。
	2) 基于新的存储格式，现在加解密的文件io更快
	3) 支持了全大小文件的加密处理(现在不会再报错)
	4) 使用Chacha20基于nonce的算法，每个文件现在有不同的特征量
	5) 扩充b58到b60使编码更紧凑
	6) calibration_amount 为 -1 时将加密整个文件

12. 2024.2.13
	0) 此版本不具有向前兼容性!!!
	1) 默认使用更快的argon2_cffi和更安全的参数
	2) 扩充b60到b72使编码更紧凑
	3) 设calibration_amount参数默认值为2048
	4) 分离模块到thirdmod文件夹

13. 2025.9.7.11.56.PM.Sunday
	0) 此版本不具有向前兼容性!!!
	1) 更新了base72编码算法及其字符表，修复Windows下以base72重命名时可能触发的错误及解码错误
	2) 添加了一个命令行参数用以指定扫描路径

14. 2025.10.9.6.13.PM.Thursday
	0) 微调字节操作实现以增加性能

15. 2025.11.10.2.30.AM.Monday
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
