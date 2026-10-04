# Hilldust

[English README](README.md)

（非官方）*Hillstone™ Secure Connect VPN 客户端*的另一个 Linux 实现。

> fork 自 [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust)。
> 上游是一个概念验证项目，最后一次提交是 2020-04-22。
> 本仓库的改动见[与上游的差异](#与上游的差异)。

---

## 请先读这一节：上游会改写你宿主机的网络

上游的 `platform_linux.py` 在隧道建立的那一刻会做这些事：

```python
subprocess.check_call('ip route replace default metric 0 via ' + str(c.gateway_ipv4), shell=True)

with open('/etc/resolv.conf', 'rb') as f:
    nameserver_bak = f.read()
with open('/etc/resolv.conf', 'wb') as f:
    for dns in c.dns_ipv4:
        f.write(('nameserver ' + str(dns) + '\n').encode('ascii'))
```

带来四个后果：

1. **默认路由是被"替换"而不是"新增"。** 这台机器发出的每一个包 —— 来自所有进程、
   所有容器、你当前开着的每一条 SSH 会话 —— 全都被改道进隧道。没有任何分流开关。
2. **`/etc/resolv.conf` 被原地覆写**，而它唯一的备份只存在于进程内存里。
3. **还原逻辑不保证会执行。** 它只在正常退出（`input('Enter to exit.')` / `Ctrl-C`）
   时才触发。`SIGTERM`、`SIGKILL`、进程崩溃、被 OOM 杀掉，或者仅仅是你启动它的那条
   SSH 会话断开，都会跳过还原。
4. **还原逻辑本身也是破坏性的。** 它会先执行 `ip route flush table main`，再执行
   `ip route restore`，用的却是连接建立那一刻抓取的快照。这期间由 Docker、
   WireGuard 或 DHCP 续约新增的路由会被清掉，且不会被还原。

### 我们的动机

我们想继续使用山石网关，但不想接受上面任何一条，也不想再用厂商的 macOS 客户端 ——
那是一个未签名的二进制，会安装一个从**用户可写目录**里执行代码的 root `LaunchDaemon`，
外加一个每 5 秒跑一次的 root shell。

于是这个 fork 把 hilldust 放进**拥有独立网络命名空间的容器**里运行：即使上游那些写入
仍然存在，它们也只会落在一个用完即弃的 namespace 里，`docker compose down` 一删了之。
除此之外，本 fork 还从源头上不再做其中大部分事情 —— 见下。

---

## 与上游的差异

| 方面 | 上游 | 本 fork |
| --- | --- | --- |
| 默认路由 | 直接替换 | 不碰它；改为并列添加两条 `/1` 路由，退出时删除；崩溃也不会断网 |
| 路由还原 | 先 flush 整张表，再恢复过期快照 | 只删除自己添加的那几条 |
| **ESP 数据面** | scapy 为每个报文构造 Packet 对象 | 直接用 `cryptography` —— **同一链路上实测 0.8 MB/s → 9.5 MB/s** |
| tun MTU | 系统默认（1500） | 1380，与厂商客户端的 `VnicMTU` 一致，避免分片 |
| socket 缓冲 | 系统默认 | 4 MiB，用 `SO_*BUFFFORCE`（容器有 `CAP_NET_ADMIN`） |
| 加密套件 | 只支持 3DES-CBC + HMAC-SHA1-96，否则 `NotSupported` | 查找表；新增当前网关协商的 AES-128-CBC + HMAC-MD5-96 |
| TLS 初始化 | `ssl.wrap_socket()`（Python 3.12 已移除） | `SSLContext`，可在 3.12+ 运行 |
| 报文分帧 | 假设一次 `recv()` 就是一个完整包 | 按声明长度精确读取 |
| 隧道假死 | 无法感知，进程空转 | 数据面探测（经隧道查 DNS）→ 拆掉并指数退避重连 |
| 退出 | `input()` 阻塞；SIGTERM 跳过清理 | SIGINT/SIGTERM 都会拆掉网络后退出 |
| 报错 | 只抛 `AuthError`，没有原因 | 带上网关返回的状态码与文本 |
| 测试 | 无 | `selftest.py` 锁死 ESP 字节格式；格式被破坏则镜像构建失败 |

## 性能

同一网关、同一链路，经隧道下载 10 MB：

| | 吞吐 | 实测 CPU 上限 |
| --- | --- | --- |
| 上游（scapy 版 ESP） | 0.80 MB/s（6.4 Mbps） | 7.8 Mbps |
| 本 fork（`cryptography` 版 ESP） | **9.5 MB/s（76 Mbps）** | 445 Mbps |

替换之前，`cryptography` 版本已与 scapy 的输出**逐字节比对**（覆盖所有填充余数、
双向验证）确认一致，之后才换上去；`selftest.py` 把这个格式冻结成回归测试，
未来任何改动都不可能悄悄破坏与网关的互操作性。

## 快速开始（Docker，推荐）

```bash
cp secret.env.example secret.env
$EDITOR secret.env          # 网关地址、用户名、密码
chmod 600 secret.env

docker compose build        # 会运行 selftest.py，格式不对则构建失败
docker compose up -d
docker compose logs -f      # 期望看到 "tunnel up on tun0 (mtu 1380)"
docker compose ps           # 期望 healthy
```

SOCKS5 代理会发布在宿主机的 `127.0.0.1:1080`。**只绑回环是有意为之** ——
从别的机器访问请走 SSH 转发，而不是把开放代理暴露给整个局域网：

```bash
ssh -N -L 1080:127.0.0.1:1080 <host>
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

这个代理是**全局隧道**：你交给它的任何流量都会从远端网关出去，而不是你的本地线路。
请只把需要走隧道的域名指过来。

### 可调参数

| 环境变量 | 默认 | 作用 |
| --- | --- | --- |
| `HILLDUST_MTU` | 1380 | tun MTU；若大包仍然丢失可继续调低 |
| `HILLDUST_LIVENESS` | 开 | 设为 `off` 关闭数据面探测 |
| `HILLDUST_LIVENESS_INTERVAL` | 15 | 两次探测间隔（秒） |
| `HILLDUST_LIVENESS_FAILURES` | 3 | 连续失败多少次后重连 |

### 依赖要求

* 宿主机存在 `/dev/net/tun`
* 需要 `NET_ADMIN` 和该设备 —— 不需要 `--privileged`，不需要 `network_mode: host`

## 另一种方式：直接在宿主机上跑

```bash
sudo HILLSTONE_PASSWORD=... ./hilldust.py vpn.example.com:10443 username
```

`sudo` 是必需的，因为要创建 tun 设备并修改路由表。密码通过环境变量传入，
不会出现在 `ps` 里。

由于改成了非破坏性路由，进程崩溃不再把机器搞断网：原本的默认路由还在，只是被两条
`/1` 路由遮住，删掉即可恢复：

```bash
sudo ip route del 0.0.0.0/1; sudo ip route del 128.0.0.0/1
```

## 代码结构

    hillstone.py       协议、TLS 控制通道、算法协商
    esp.py            基于 cryptography 的 ESP 数据面
    tunnel.py         UDP 隧道客户端
    platform_linux.py tun 设备、路由、resolver
    hilldust.py       CLI、会话循环、重连、信号处理
    selftest.py       ESP 格式的已知答案与不变量测试
    probe.py          TLS + ESP 检查，不尝试登录
    probe2.py         打印协商出的算法（会登录）

## 排障脚本

| 脚本 | 作用 | 是否登录 |
| --- | --- | --- |
| `selftest.py` | ESP 格式回归测试 | 否 |
| `probe.py` | TLS 握手 + 对 `IPSEC_ALGOS` 每一项做一次 ESP 往返 | **否** |
| `probe2.py` | 打印 NEW_KEY 应答，即协商出的算法 | 是 |

```bash
docker compose run --rm --no-deps --entrypoint python3 \
  -v "$PWD/probe2.py:/probe2.py:ro" vpn /probe2.py
```

`probe.py` 会在发送 AUTH 之前停下，因此探测网关永远不会记录一次登录失败。
当网关协商出不支持的算法时，`probe2.py` 告诉你具体是哪一对 —— 而支持它只需要在
`IPSEC_ALGOS` 里加一行，并在 `esp.py` 里补上对应的原语。

## 已知限制

* 源自概念验证项目，请据此评估。
* 不支持设备绑定：`HOST_ID` / `HOST_NAME` 发送为空字符串。配置了主机检查的网关会拒绝登录。
* 不校验网关证书 —— 与厂商客户端一致（其配置项为 `VerifyServerCert=false`）。
  这买到的是机密性，不是身份认证。
* ESP 的初始向量在会话生命周期内固定，这是厂商协议的规定。属于 CBC 模式的固有弱点，
  不是本 fork 能单方面修掉的。
* 存活判定依赖数据面。如果网关停止响应探测目标但仍在转发流量，会导致不必要的重连；
  遇到这种情况可设 `HILLDUST_LIVENESS=off`。

## 致谢与许可

上游项目：[LionNatsu/hilldust](https://github.com/LionNatsu/hilldust)，GPLv3。
Hillstone、Hillstone Secure Connect 等名称归山石网科（Hillstone Networks）所有。
本项目为非官方项目，与其无任何关联。
