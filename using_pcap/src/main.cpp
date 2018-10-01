#include <iostream>
#include <pcap.h>

void callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    std::cout << "Got a packet with " << hdr->len << " bytes\n";
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    if(dev != nullptr){
        std::cout << "Default device: " << dev << std::endl;
    } else {
        std::cout << "Could not open a default device" << std::endl;
        exit(1);
    }
    pcap_t* handle;
    struct bpf_program bfp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        std::cout << "Could not get netmask for device" << std::endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        std::cout << "Couldn't open " << dev << ": " << errbuf << std::endl;
        exit(1);
    }
    if((pcap_compile(handle, &bfp, "port 53", 0, net) == -1)
       || (pcap_setfilter(handle, &bfp) == -1)){
        std::cout << "Could not parse or set filter" << std::endl;
        exit(1);
    }
    pcap_loop(handle, 5, callback, NULL);
    pcap_close(handle);
}
