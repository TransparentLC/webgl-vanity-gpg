# webgl-vanity-gpg

使用 GPU（WebGL）快速生成带有“靓号”的 PGP 密钥！

“靓号”指的是带有连号等特定格式的密钥指纹或 ID（例如以 `77777777` 结尾），具体介绍和生成原理请参见：

* [一位 PGP 进步青年的科学算号实践](https://www.douban.com/note/763978955/)
* [某科学的 PGP 算号指南](https://blog.dejavu.moe/posts/the-scientific-vanity-pgp-counting-guide/)

![](https://github.com/user-attachments/assets/e6364d93-fffe-4fcd-9857-b70155e6f476)

简单来说，密钥指纹是密钥生效时间和公钥内容的 SHA-1，通过不断生成密钥和修改时间（成本更低）的暴力遍历方式找到“靓号”。

目前速度最快的算号工具，例如使用 CPU 的 [RedL0tus/VanityGPG](https://github.com/RedL0tus/VanityGPG) 和使用 GPU 的 [cuihaoleo/gpg-fingerprint-filter-gpu](https://github.com/cuihaoleo/gpg-fingerprint-filter-gpu)，都只能在 Linux 下运行，后者还需要准备 CUDA 环境。但是我是 Windows 用户，又觉得开虚拟机跑 VanityGPG 太慢了，更没有多余的显卡拿去直通给虚拟机，所以就写了这个。

能在浏览器上运行的话那应该就方便多了！(๑•̀ᄇ•́)و ✧

## 类似工具和性能对比

| Repo | 计算方式 | 速度（hash/s） | 注释 |
| - | - | - | - |
| [Erriy/gpg_awesome_keyid](https://github.com/Erriy/gpg_awesome_keyid) | CPU | 17k | i5-5200U x4 |
| [nc7s/g3k](https://github.com/nc7s/g3k) | CPU | 430k | M1 Pro x8 |
| [RedL0tus/VanityGPG](https://github.com/RedL0tus/VanityGPG) | CPU | 120m | Ryzen 7 3700x x16 |
| [lachesis/scallion](https://github.com/lachesis/scallion) | GPU |  | 仅支持 RSA，已停止更新 |
| [Victrid/memorable-pgpgen](https://github.com/Victrid/memorable-pgpgen) | GPU |  | 没有给出速度 |
| [cuihaoleo/gpg-fingerprint-filter-gpu](https://github.com/cuihaoleo/gpg-fingerprint-filter-gpu) | GPU | 10b | RTX 3090 数据来自“算号指南” |
| 这个项目 | GPU | 2b | GTX 1070 |
| 这个项目 | GPU | 7b | RTX A5500 |

以上的速度均为生成 Curve25519 类型的密钥的速度。

## 合并主密钥和子密钥

这个工具在生成密钥时只能保证主密钥和子密钥**其中之一**的指纹为“靓号”。如果你希望生成主密钥和子密钥的指纹都是“靓号”的密钥：

1. 生成主密钥为“靓号”的私钥 A。
2. 生成子密钥为“靓号”的私钥 B（需要勾选“将格式应用到子密钥而不是主密钥上”）。
3. 点击“把不同密钥的“靓号”合并到一起！”，粘贴私钥 A 和私钥 B，然后保存合并后的私钥。
4. 导入新的私钥后，自行使用 `gpg --edit-key` 编辑私钥。
