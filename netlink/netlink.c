#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <linux/types.h>

#define _SEQ 0xefbe // netlink.hdr_seq == 0xefbe (wireshark filter)
#define _PID 0x3e3e
#define _FLAGS 0
#define _MAX_RCV 8192
#define _MAX_NLMSG 4096 // page size on this machine

#define _DEBUG 0
#define _REPEAT 1 // keep sending NL msg until Ctrl-C

#define FIRST_NLA(nh) ((struct nlattr*)((char*)NLMSG_DATA(nh) + GENL_HDRLEN))
#define NLA_NEXT(nla) ((struct nlattr*)((char*)nla + NLA_ALIGN(nla->nla_len)))

int setup_nl_sock(struct sockaddr_nl* sock)
{
    memset(sock, 0, sizeof(*sock));
    sock->nl_family = AF_NETLINK;
    sock->nl_groups = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if(fd == -1){
        return -1;
    }
    int rc = bind(fd, (struct sockaddr *) sock, sizeof(*sock));
    if(rc != 0){
        return -1;
    }
    return fd;
}

void close_nl_sock(int fd)
{
    if(fd > 0)
        close(fd);
}

void dump_mem_addr(unsigned char* ptr, size_t bytes);

/* create a nlmsghdr with generic netlink header */
struct nlmsghdr* genlmsg_create(__u16 type, __u16 flags, __u32 seq, __u32 pid,
                                __u8 ge_cmd, __u8 ge_version)
{
    struct nlmsghdr *nh = malloc(_MAX_NLMSG);
    if(!nh)
        return NULL;
    // header
    nh->nlmsg_type = type;
    if(!flags)
        nh->nlmsg_flags = NLM_F_REQUEST;
    else
        nh->nlmsg_flags = flags;
    nh->nlmsg_seq = seq;
    nh->nlmsg_pid = pid;
    nh->nlmsg_len = NLMSG_HDRLEN;
    // generic netlink header
    struct genlmsghdr ghdr;
    ghdr.cmd = ge_cmd;
    ghdr.version = ge_version;
    memcpy(NLMSG_DATA(nh), &ghdr, sizeof(ghdr));
    nh->nlmsg_len = NLMSG_ALIGN(NLMSG_HDRLEN + sizeof(ghdr));
    return nh;
}

void genlmsg_free(struct nlmsghdr **nh)
{
    free(*nh);
    *nh = NULL;
}

/* append a nlattr struct and payload to a nlmsghdr */
int put_nlattr(struct nlmsghdr* nh, __u16 attrtype, char* data, size_t len)
{
    assert(nh);
    int totlen = nh->nlmsg_len + NLA_HDRLEN + len;
    assert(totlen < _MAX_NLMSG);
    struct nlattr nla = {
        NLA_HDRLEN + NLA_ALIGN(len),
        attrtype
    };
    unsigned char* end = (unsigned char*)((char*)nh+nh->nlmsg_len);
    memcpy(end, &nla, NLA_HDRLEN);
    memcpy(end+NLA_HDRLEN, data, len);
    nh->nlmsg_len = NLMSG_ALIGN(totlen);
    return NLMSG_ALIGN(totlen);
}

int genlmsg_send(struct sockaddr_nl* sock, int fd, struct nlmsghdr* nh)
{
    struct iovec iov = { nh, nh->nlmsg_len };
    struct msghdr msg = { sock, sizeof(*sock), &iov, 1, NULL, 0, 0 };
    int rc = sendmsg(fd, &msg, 0);
    if(rc == -1)
        return -ECOMM;
    return fd;
}

/* recv netlink messages into buf */
size_t genlmsg_recv(struct sockaddr_nl* sock, int fd, char* buf, size_t len)
{
    struct iovec iov = { buf, len };
    struct msghdr msg = { sock, sizeof(*sock), &iov, 1, NULL, 0, 0 };
    size_t sz = recvmsg(fd, &msg, 0);
#if _DEBUG
    printf("nl: recv %zu bytes\n", sz);
#endif
    return sz;
}

/* recv netlink messages and look for the specified attribute */
int genlmsg_recv_get_u32_attr(struct sockaddr_nl* sock, int fd, int type, uint32_t* dst)
{
    char buf[_MAX_RCV];
    size_t len = genlmsg_recv(sock, fd, buf, sizeof(buf));
    struct nlmsghdr *rh;
    for(rh = (struct nlmsghdr*)buf; NLMSG_OK(rh, len); rh = NLMSG_NEXT(rh, len)){
        if(rh->nlmsg_type == NLMSG_ERROR) {
            int err = (*(int32_t*)NLMSG_DATA(rh));
            if(err == 0) continue; // ACK
            return err;
        }
        struct nlattr* nla = FIRST_NLA(rh);
        size_t i = NLMSG_LENGTH(GENL_HDRLEN);
        for(; i != rh->nlmsg_len; nla = NLA_NEXT(nla)){
            i += NLA_ALIGN(nla->nla_len);
            if(nla->nla_type == type)
                *dst = *(uint32_t*)((char*)nla+NLA_HDRLEN);
#if _DEBUG
            printf("nl: recvd attr=%d len=%d\n", nla->nla_type, nla->nla_len);
            dump_mem_addr((unsigned char*)nla, nla->nla_len);
#endif
        }
        
    }
    return 0;
}

/* 
 * shortcut when we are happy to use default values, have only one param,
 * and just want to find out an attribute value.
 * @returns 0 if successful, -1 if send/alloc error or a netlink error code
 */
int quick_ex_u32_cmd(struct sockaddr_nl* sock, int fd, __u16 type, __u8 cmd, __u8 ver,
                         int param_type, char* param, size_t param_len,
                         int attr, uint32_t* res)
{
    struct nlmsghdr *nh = genlmsg_create(type, _FLAGS, _SEQ, _PID, cmd, ver);
    if(!nh)
        return -ENOMEM;
    put_nlattr(nh, param_type, param, param_len);
#if _DEBUG
    printf("nl: allocated genlmsg with size=%d\n", nh->nlmsg_len);
    dump_mem_addr((unsigned char*)nh, nh->nlmsg_len);
#endif
    if(genlmsg_send(sock, fd, nh) == -1){
        genlmsg_free(&nh);
        return -ECOMM;
    }
    genlmsg_free(&nh);
    int err = genlmsg_recv_get_u32_attr(sock, fd, attr, res);
    if(err < 0){
        return err;
    }
    return 0;
}


/* recv netlink messages and print a summary */
int genlmsg_recv_print_dump(struct sockaddr_nl* sock, int fd, int silent)
{
    char buf[_MAX_RCV];
    size_t len = genlmsg_recv(sock, fd, buf, sizeof(buf));
    
    struct nlmsghdr *rh;
    for(rh = (struct nlmsghdr*)buf; NLMSG_OK(rh, len); rh = NLMSG_NEXT(rh, len)){
        if(rh->nlmsg_type == NLMSG_ERROR){
            int err = (*(int32_t*)NLMSG_DATA(rh));
            if (err == 0) continue; //ACK
            len = err;
            continue;
        }
        if(!silent){
            printf("recvd NLMSG, length=%d, seq=%x\n", rh->nlmsg_len, rh->nlmsg_seq);
            dump_mem_addr((unsigned char*)rh, rh->nlmsg_len);
        }
    } 
    return len;
}

/* print a buffer, for debugging purposes */
void dump_mem_addr(unsigned char* ptr, size_t bytes)
{
    for(size_t i=0; i<bytes; ++i){
        if((i > 0) && (i % 4 == 0))
            printf(" ");
        if((i > 0) && (i % 16 == 0))
            printf("\n");
        printf("%02x", *ptr);
        ptr+=1;
    }
    printf("\n");
}

int main()
{
    struct sockaddr_nl sock;
    int fd = setup_nl_sock(&sock);
    if(fd == -1){
        printf("nl: could not create netlink socket, exiting\n");
        return -1;
    }
    // identify the nl80211 protocol family ID
    uint32_t fam; 
    char nl[] = "nl80211";
    int err = quick_ex_u32_cmd(&sock, fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
                                   CTRL_ATTR_FAMILY_NAME, (char*)nl, strlen(nl)+1,
                                   CTRL_ATTR_FAMILY_ID, &fam);
    if(err < 0){
        printf("nl: quick_ex error, exiting\n");
        return -1;
    }
    // identify the device
    uint32_t ifindex = if_nametoindex("wlx503eaa4ac2d1");
    uint32_t phy = 0xFF;
    err = quick_ex_u32_cmd(&sock, fd, fam, NL80211_CMD_GET_WIPHY, 0,
                           NL80211_ATTR_IFINDEX, (char*)&ifindex, 4,
                           NL80211_ATTR_WIPHY, &phy);
    if(err < 0){
        printf("nl: GET WIPHY command failed, exiting\n");
        return -1;
    }
    printf("nl: using interface %u/phy %u\n", ifindex, phy);
    printf("nl: sending NL80211_CMD_GET_INTERFACE request\n");
    struct nlmsghdr *nh;
    char buf[_MAX_RCV];
    while(_REPEAT){
        nh = genlmsg_create(fam, _FLAGS,_SEQ, _PID,
                            NL80211_CMD_GET_INTERFACE, 0);
        if(!nh)
            goto close_sock;
        put_nlattr(nh, NL80211_ATTR_IFINDEX, (char*)&ifindex, 4);
        put_nlattr(nh, NL80211_ATTR_WIPHY, (char*)&phy, 4);
        if(genlmsg_send(&sock, fd, nh) == -1)
            goto free_nh;
        genlmsg_recv(&sock, fd, buf, sizeof(buf));
        genlmsg_free(&nh);
    }
    printf("nl: finshed cleanly\n");
free_nh:
    if(nh)
        genlmsg_free(&nh);
close_sock:
    close_nl_sock(fd);
    return 0;
}
