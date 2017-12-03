pcap_next_ex hangs forever
=

pcap_next_ex function does not wake up even if not only read_timeout elapsed, but also pcap_close is called in the other thread. See the following result. pcap_next_ex function wakes up when only filtering packet is sniffed.

```cpp
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <glog/logging.h>

volatile bool active = true;
void proc(pcap_t* handle) {
  while (active) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    LOG(INFO) << "bef call pcap_next_ex";
    int res = pcap_next_ex(handle, &header, &packet);
    LOG(INFO) << "aft call pcap_next_ex" << res;
    if (res == 0) continue;
    if (res == -1 || res == -2) {
      LOG(ERROR) << "pcap_next_ex return " << res;
      break;
    }
    printf("%u bytes captured\n", header->caplen);
  }
}

void usage() {
  LOG(INFO) << "syntax: pcap_close_test <interface>";
  LOG(INFO) << "sample: pcap_close_test wlan0";
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 4000, errbuf);
  if (handle == NULL) {
    LOG(ERROR) <<"couldn't open device " << dev << " " << errbuf;
    return -1;
  }
  struct bpf_program fp;
  if (pcap_compile(handle, &fp, "icmp", 0, 0) == -1) {
    LOG(ERROR) << "couldn't parse filter " << pcap_geterr(handle);
    return -2;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    LOG(ERROR) << "couldn't install filter " << pcap_geterr(handle);
    return -3;
  }

  std::thread th(proc, handle);

  LOG(INFO) << "bef sleep\n";
  sleep(2);
  LOG(INFO) << "bef pcap_close\n";
  pcap_close(handle);
  LOG(INFO) << "before join\n";
  th.join();
  LOG(INFO) << "after join\n";

  return 0;
}

```

```
# tcpdump --version
tcpdump version 4.9.2
libpcap version 1.8.1
OpenSSL 1.1.0g  2 Nov 2017
```

```
# ./pcap_close_test eth0
WARNING: Logging before InitGoogleLogging() is written to STDERR
I1203 23:03:10.041653 17882 main.cpp:55] bef sleep
I1203 23:03:10.041744 17883 main.cpp:13] bef call pcap_next_ex
I1203 23:03:12.043593 17882 main.cpp:57] bef pcap_close
I1203 23:03:12.043823 17882 main.cpp:59] before join
```


```
# uname -a
Linux kali 4.13.0-kali1-amd64 #1 SMP Debian 4.13.10-1kali2 (2017-11-08) x86_64 GNU/Linux
```

```
# g++ --version
g++ (Debian 7.2.0-14) 7.2.0
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

https://github.com/the-tcpdump-group/libpcap/issues/667
