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
