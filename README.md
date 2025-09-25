# RDP Scanner

一个基于 **Python + PyQt5** 的图形化 RDP 扫描器。
支持批量扫描指定网段，检测主机的 **Ping** 状态、**RDP(3389)** 端口是否开放，并获取 **主机名** 和 **MAC 地址**。


打包好的程序
链接: https://pan.baidu.com/s/1BPzPYWP3RpTOsNezmAEzKw?pwd=312q 提取码: 312q
## ✨ 功能特性

* 批量扫描指定网段 IP
* 并发扫描（可自定义线程数）
* 支持跳过 Ping 或端口检测
* 扫描结果实时显示在表格中
* 自动分类结果（仅 Ping 通、仅 RDP 通、都通、都不通）
* 右键复制 IP
* 显示主机名和 MAC 地址

---

## 🚀 使用方法

1. 运行程序：

   ```bash
   python rdp_scanner.py
   ```

2. 在界面中输入：

   * **IP 前缀**（例如 `192.168.1`）
   * **起始/结束 IP**
   * **线程数**
   * **Ping / RDP 超时时间**
   * 勾选是否跳过 `Ping` 或 `端口检测`

3. 点击 **开始扫描** 按钮即可。

---


## ⚠️ 注意事项

* **Windows 下** 扫描会调用 `ping` 和 `arp` 命令，请确保系统自带。
* **Linux/Mac 下** 会使用 `ping -c` 和 `arp -n`。
* 需要在 **局域网环境** 使用，部分设备可能禁止 ICMP 或 RDP 端口探测。

---

## 📜 License

本项目使用 **MIT License**，可自由使用与修改。

