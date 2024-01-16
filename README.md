# NPU TCP/IP网络协议栈

本协议栈是在西北工业大学学长们的代码的基础上，经整合，重构，适配而成，支持
Ethernet,IPv4,ARP,ICMP和UDP协议的部分功能，client和server是一个验证程序。

本协议栈需要安装make

```shell
    sudo apt-get install make build-essential
```

使用以下命令编译：

```shell
    make all
```

如果报错，使用一下命令清除编译目标后再次编译：

```shell
    make clean
```

使用以下命令可以运行服务器程序：

```shell
    make server
```

使用一下命令可以运行客户程序：

```shell
    make client
```
