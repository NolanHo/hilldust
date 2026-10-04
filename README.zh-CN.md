# Hilldust

[English README](README.md)

（非官方）*Hillstone™ Secure Connect VPN 客户端*的另一个 Linux 实现。

> 本仓库 fork 自 [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust)。
> 上游是一个概念验证项目，最后一次提交是 2020-04-22。本仓库的改动见
> [本 fork 增加了什么](#本-fork-增加了什么)。

---

## 请先读这一节：hilldust 会改写你宿主机的网络

`platform_linux.py` —— **上游未修改的代码** —— 在隧道建立的那一刻会做这些事：

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
3. **还原逻辑不保证会执行。** `restore_network()` 只在正常退出时才被调用：

   ```python
   try:
       input('Enter to exit.')
   except KeyboardInterrupt:
       pass
   platform_linux.restore_network(c)
   ```

   `SIGTERM`、`SIGKILL`、进程崩溃、被 OOM 杀掉，或者仅仅是你启动它的那条 SSH 会话断开，
   都会跳过还原。留给你的是一条被改写的默认路由和一个被覆写的 DNS ——
   而这台机器自身的连通性，此刻已经依赖上了一条早就不在运行的隧道。
4. **还原逻辑本身也是破坏性的。** 它会先执行 `ip route flush table main`，再执行
   `ip route restore`，用的却是连接建立那一刻抓取的快照。如果这期间 Docker、
   WireGuard 或 DHCP 续约新增了路由，它们会被清掉，且不会被还原。

在一台用完即弃的笔记本上，这只是烦人。在一台同时跑着 WireGuard 网状网、Docker 网桥和
别人服务的服务器上，这就是一次等着某个永远等不到的 `Ctrl-C` 来触发的故障。

### 我们的动机

我们想继续使用山石网关，但不想接受上面任何一条，也不想再用厂商的 macOS 客户端 ——
那是一个未签名的二进制，会安装一个从**用户可写目录**里执行代码的 root `LaunchDaemon`，
外加一个每 5 秒跑一次的 root shell。

于是这个 fork 把 hilldust 放进**拥有独立网络命名空间的容器**里运行。上面两处破坏性写入
因此落在容器的 netns 内，而 `docker compose down` 直接删除整个 namespace 就完成了还原。
宿主机保持自己的路由、自己的 DNS，并且不会多出任何 tun 设备。

容器同时解决了第二个问题：上游 hilldust 只实现了 3DES-CBC + HMAC-SHA1-96，
而现在的山石网关协商的是 AES-128-CBC + HMAC-MD5-96。详见[补丁](#补丁)。

---

## 本 fork 增加了什么

| 文件 | 用途 |
| --- | --- |
| `patches/0001-*.patch` | 增加 AES-128-CBC + HMAC-MD5-96 支持 |
| `shim/sitecustomize.py` | 补回 Python 3.12 中被移除的 `ssl.wrap_socket()` |
| `Dockerfile`、`compose.yaml`、`entrypoint.sh` | 在受限容器中运行，并暴露 SOCKS5 |
| `probe.py`、`probe2.py`、`probe3.py` | 不靠猜的排障脚本 |
| `secret.env.example` | 凭据模板 |

上游的 `.py` 文件保持逐字节不变；所有改动都在镜像构建时应用，保证差异可审阅。

## 快速开始（Docker，推荐）

```bash
cp secret.env.example secret.env
$EDITOR secret.env          # 网关地址、用户名、密码
chmod 600 secret.env

docker compose build
docker compose up -d
docker compose logs -f      # 期望看到 "Network configured."
```

SOCKS5 代理会发布在宿主机的 `127.0.0.1:1080`。**只绑回环是有意为之** ——
从别的机器访问请走 SSH 转发，而不是把开放代理暴露给整个局域网：

```bash
ssh -N -L 1080:127.0.0.1:1080 <host>
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

注意这个 SOCKS 代理是**全局隧道**：容器的默认路由走 VPN，所以你交给它的任何流量都会
从远端网关出去，而不是你的本地线路。请只把需要走隧道的域名指过来。

### 依赖要求

* 宿主机存在 `/dev/net/tun`
* 容器需要 `NET_ADMIN` 和该 tun 设备，仅此而已
* 不需要 `--privileged`，不需要 `--network host`

## 另一种方式：直接在宿主机上跑

如果你能接受上面那些代价（一次性虚拟机、实验机器、你自己的隔离命名空间），
上游的用法依然有效：

```bash
sudo ./hilldust.py vpn.example.com:10443 username password
```

`sudo` 是必需的，因为要创建 tun 设备并修改路由表。

## 补丁

除非网关在 NEW_KEY 交换中返回 `ENC_ALG=3`（3DES-CBC）和 `AUTH_ALG=2`
（HMAC-SHA1-96），否则上游会直接抛 `NotSupported` 中止：

```python
if res[Payload.ENC_ALG] != b'\0\x03' or res[Payload.AUTH_ALG] != b'\0\x02' or ...:
    raise NotSupported
```

而当前网关返回的是 `ENC_ALG=12`（aes128_cbc）/ `AUTH_ALG=1`（hmac-md5-96）。
补丁把硬编码判断换成一张 `(ENC_ALG, AUTH_ALG)` → 算法及其密钥/IV 长度的查找表，
并把协商结果交给 scapy。要再支持一种套件，只需在 `IPSEC_ALGOS` 里加一行。

控制通道不受影响 —— 它是 TLS，与 ESP 数据通道各自独立协商。

## 排障脚本

| 脚本 | 作用 | 是否登录 |
| --- | --- | --- |
| `probe3.py` | 打印 scapy 支持的算法与密钥长度 | 否 |
| `probe.py` | TLS 握手 + 垫片检查 | **否** |
| `probe2.py` | 打印 NEW_KEY 应答，即协商出的算法 | 是 |

```bash
docker compose run --rm --no-deps --entrypoint python3 \
  -v "$PWD/probe2.py:/probe2.py:ro" vpn /probe2.py
```

`probe.py` 会在发送 AUTH 之前主动停下，因此探测网关永远不会增加它的登录失败计数。

## 已知限制

* 这是一个概念验证。上游最后一次提交为 2020-04-22，请据此评估。
* 不支持设备绑定：`HOST_ID` / `HOST_NAME` 发送为空字符串。配置了主机检查的网关会拒绝登录。
* 不校验网关证书。上游不校验，本 fork 不校验，厂商自己的 macOS 客户端也不校验
  （其配置项为 `VerifyServerCert=false`）。
* 如果 UDP 数据通道中断，hilldust 自身不会察觉。容器会重启它，但会先等待
  `RESTART_BACKOFF`（默认 30 秒），以免凭据错误时反复撞网关导致账号被锁。

## 致谢与许可

上游项目：[LionNatsu/hilldust](https://github.com/LionNatsu/hilldust)，GPLv3。
Hillstone、Hillstone Secure Connect 等名称归山石网科（Hillstone Networks）所有。
本项目为非官方项目，与其无任何关联。
