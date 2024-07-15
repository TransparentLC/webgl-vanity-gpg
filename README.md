# webgl-vanity-gpg

使用 GPU（WebGL）快速生成带有“靓号”的 PGP 密钥！

“靓号”指的是带有连号等特定格式的密钥指纹或 ID（例如以 `77777777` 结尾），具体介绍和生成原理请参见：

* [一位 PGP 进步青年的科学算号实践](https://www.douban.com/note/763978955/)
* [某科学的 PGP 算号指南](https://blog.dejavu.moe/posts/the-scientific-vanity-pgp-counting-guide/)

目前速度最快的算号工具，例如使用 CPU 的 [RedL0tus/VanityGPG](https://github.com/RedL0tus/VanityGPG) 和使用 GPU 的 [cuihaoleo/gpg-fingerprint-filter-gpu](https://github.com/cuihaoleo/gpg-fingerprint-filter-gpu)，都只能在 Linux 下运行，后者还需要准备 CUDA 环境。但是我是 Windows 用户，又觉得开虚拟机跑 VanityGPG 太慢了，更没有多余的显卡拿去直通给虚拟机，所以就写了这个。

生成 Curve25519 的密钥时，VanityGPG 使用 AMD Ryzen 7 3700x 和 16 线程每秒可以尝试 1.2 亿个 hash，而这个项目即使是使用几年前的 GTX 1070 就可以轻松达到 8 亿的速度。
