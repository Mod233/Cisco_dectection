#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/types.h>
#include <cmath>
#include <algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <cmath>
#include <vector>
#include <netinet/udp.h>
#include <dirent.h>
#ifdef linux
#include <unistd.h>
#include <dirent.h>
#elif WIN32
#include <direct.h>
#endif
std::map<std::string,int> show;
#define DEBUG 1
#define DIR 0
int tcp_noack(char*dir, std::string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    std::cout<<"pcap_file_header "<<sizeof(pcap_file_header)<<std::endl;
    std::cout<<"pcap_pkthdr "<<sizeof(pcap_pkthdr)<<std::endl;
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        exit(1);
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr,&hdr);
    	if(packet == NULL){
    		printf("Finish reading!\n");
    		break;
    	}
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip,dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 6) continue;
    	if(ntohs(ipptr->tot_len) < 42) continue;
    	tcpptr = (struct tcphdr *)(packet+sizeof(ether_header)+sizeof(iphdr));
    	std::string sip=inet_ntoa(srcip);
    	std::string dip=inet_ntoa(dstip);
    	std::string name;
    	name = min(sip, dip) + '-' + max(sip, dip);
    	FILE* pFile;
    	if(show.count(name))
    		show[name]++;
    	else show[name]=0;
    	std::string filedir = result + "/tcp_noack/" + name;
    	int flag = mkdir(filedir.c_str(), 0777);
   // 	if(flag!=0) printf("mkdir file %s failed\n", filedir.c_str());
    	if(show[name]%300!=0){
    		char filename[100];
    		sprintf(filename, "%s/%s-%s-%d.pcap", filedir.c_str(), min(sip, dip).c_str(), max(sip, dip).c_str(), show[name]/300);
    		pFile=fopen(filename, "a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
//    		printf("# %d\n", show[name]);
    		pcap_file_header ph;
    		ph.magic=0xa1b2c3d4;
    		ph.version_major=0x02;
    		ph.version_minor=0x04;
    		ph.thiszone=0;
    		ph.sigfigs=0;
    		ph.snaplen=65535;
    		ph.linktype=0x1;
    		char filename[100];
    		sprintf(filename, "%s/%s-%s-%d.pcap", filedir.c_str(), min(sip, dip).c_str(), max(sip, dip).c_str(), show[name]/300);
    		pFile=fopen(filename, "w");
    		fwrite(&ph,1,24,pFile);
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    }
    printf("Finish tcp_noack\n");
    return 0;
}



//int read_file(char* base_dir, std::string result){
//	DIR* pdir;
//	struct dirent *ent;
//	char childpath[512];
//	pdir = opendir(base_dir);
//	memset(childpath,0,sizeof(childpath));
//	while((ent = readdir(pdir))!=NULL){
//		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
//		if(ent->d_type & DT_DIR){
//			if((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) continue;
//			read_file(childpath, result);
//		}
//		else{
//		    tcp_noack(childpath, result);
//		}
//	}
//	return 0;
//}





int main(int argc, char **argv){
	printf("hello world\n");
    return 0;
}


