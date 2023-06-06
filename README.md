---
description: Based on Linux-4.14.316
---

# UDP sendto EAGAIN

&#x20;       使用TCP scoket发送数据的时候，内核会将用户态数据copy到TCP socket的send buffer中。如果调用send/sendmsg返回EAGAIN错误(sockfd需要设置为noblocking)，则意味着send buffer已满，需要暂停发送。TCP socket收到receiver发送的ACK并删除掉send buffer中已确认的data之后有了足够的空间后，epoll会返回EPOLLOUT event，这时用户态TCP socket就可以继续发送data了。

&#x20;       UDP协议是无连接的，用UDP sendto发送数据的时候也会出现EAGAIN错误吗？答案是：会出现。它是否有send buffer? 什么情况下才会通过epoll返回EPOLLOUT event通知user继续发送了呢？我们来看看linux kernel source code.

&#x20;       UDP sendto系统调用对应kernel的函数是udp\_sendmsg：

```c
870 int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)                                                                                                                                       
871 {
872     struct inet_sock *inet = inet_sk(sk); 
873     struct udp_sock *up = udp_sk(sk);
874     struct flowi4 fl4_stack;
875     struct flowi4 *fl4;  
876     int ulen = len;      
877     struct ipcm_cookie ipc;
878     struct rtable *rt = NULL;
879     int free = 0;        
880     int connected = 0;   
881     __be32 daddr, faddr, saddr;    
882     __be16 dport;        
883     u8  tos;
884     int err, is_udplite = IS_UDPLITE(sk);
885     int corkreq = READ_ONCE(up->corkflag) || msg->msg_flags&MSG_MORE;
886     int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);                                                                                                                                   
887     struct sk_buff *skb;
...
1044 back_from_confirm:
1045 
1046     saddr = fl4->saddr;
1047     if (!ipc.addr)
1048         daddr = ipc.addr = fl4->daddr;
1049 
1050     /* Lockless fast path for the non-corking case. */
1051     if (!corkreq) {
1052         skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
1053                   sizeof(struct udphdr), &ipc, &rt,
1054                   msg->msg_flags);
1055         err = PTR_ERR(skb);
1056         if (!IS_ERR_OR_NULL(skb))
1057             err = udp_send_skb(skb, fl4);
1058         goto out;
1059     }
1060 
1061     lock_sock(sk);
1062     if (unlikely(up->pending)) {
1063         /* The socket is already corked while preparing it. */
1064         /* ... which is an evident application bug. --ANK */
1065         release_sock(sk);
1066 
1067         net_dbg_ratelimited("socket already corked\n");
1068         err = -EINVAL;
1069         goto out;
1070     }
1071     /*
1072      *  Now cork the socket to pend data.
1073      */
1074     fl4 = &inet->cork.fl.u.ip4;
1075     fl4->daddr = daddr;
1076     fl4->saddr = saddr;
1077     fl4->fl4_dport = dport;
1078     fl4->fl4_sport = inet->inet_sport;
1079     up->pending = AF_INET;
1080 
1081 do_append_data:
1082     up->len += ulen;
1083     err = ip_append_data(sk, fl4, getfrag, msg, ulen,
1084                  sizeof(struct udphdr), &ipc, &rt,
1085                  corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
1086     if (err)
1087         udp_flush_pending_frames(sk);
1088     else if (!corkreq)
1089         err = udp_push_pending_frames(sk);
1090     else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
1091         up->pending = 0;
1092     release_sock(sk);
```

* 885: corkreq非0意味着开启了CORK功能，即塞子；这个功能允许user先禁止kernel socket发送任何data，然后user将data copy到socket的send buffer(sk\_write\_queue)中，再用setsockopt拔掉“塞子”；拔掉之后buffer中数据会一起被发送出去；这里先不讨论这种情况；
* 1051-1058: 没用开启CORK的时候，会调用ip\_make\_skb()生成skb再调用udp\_send\_skb()进行发送；

```c
1484 struct sk_buff *ip_make_skb(struct sock *sk,
1485                 struct flowi4 *fl4,
1486                 int getfrag(void *from, char *to, int offset,
1487                     int len, int odd, struct sk_buff *skb),
1488                 void *from, int length, int transhdrlen,
1489                 struct ipcm_cookie *ipc, struct rtable **rtp,
1490                 unsigned int flags)
1491 {       
1492     struct inet_cork cork;
1493     struct sk_buff_head queue;
1494     int err;
1495 
1496     if (flags & MSG_PROBE)
1497         return NULL;
1498     
1499     __skb_queue_head_init(&queue);
1500     
1501     cork.flags = 0;
1502     cork.addr = 0;
1503     cork.opt = NULL;
1504     err = ip_setup_cork(sk, &cork, ipc, rtp);
1505     if (err)
1506         return ERR_PTR(err);
1507                  
1508     err = __ip_append_data(sk, fl4, &queue, &cork,
1509                    &current->task_frag, getfrag,
1510                    from, length, transhdrlen, flags);
1511     if (err) {
1512         __ip_flush_pending_frames(sk, &queue, &cork);
1513         return ERR_PTR(err);
1514     }
1515 
1516     return __ip_make_skb(sk, fl4, &queue, &cork);
1517 }
```

* 1499: 初始化一个临时send buffer，仅用于这一次send；
* 1508-1510: 将用户态data copy到skb中并将skb放入到queue里；
* 1516: 将queue里面所有的skb都append到一个skb，并初始化IP header部分；

先看：\_\_ip\_make\_skb():

```c
1331 /*
1332  *  Combined all pending IP fragments on the socket as one IP datagram
1333  *  and push them out.
1334  */
1335 struct sk_buff *__ip_make_skb(struct sock *sk,
1336                   struct flowi4 *fl4,
1337                   struct sk_buff_head *queue,
1338                   struct inet_cork *cork)
1339 {
1340     struct sk_buff *skb, *tmp_skb;
1341     struct sk_buff **tail_skb;
1342     struct inet_sock *inet = inet_sk(sk);
1343     struct net *net = sock_net(sk);
1344     struct ip_options *opt = NULL;
1345     struct rtable *rt = (struct rtable *)cork->dst;
1346     struct iphdr *iph;
1347     __be16 df = 0;
1348     __u8 ttl;
1349 
1350     skb = __skb_dequeue(queue);
1351     if (!skb)
1352         goto out;
1353     tail_skb = &(skb_shinfo(skb)->frag_list);
1354 
1355     /* move skb->data to ip header from ext header */
1356     if (skb->data < skb_network_header(skb))
1357         __skb_pull(skb, skb_network_offset(skb));
1358     while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
1359         __skb_pull(tmp_skb, skb_network_header_len(skb));
1360         *tail_skb = tmp_skb;
1361         tail_skb = &(tmp_skb->next);
1362         skb->len += tmp_skb->len;
1363         skb->data_len += tmp_skb->len;
1364         skb->truesize += tmp_skb->truesize;
1365         tmp_skb->destructor = NULL;
1366         tmp_skb->sk = NULL;
1367     }
1368 
1369     /* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
1370      * to fragment the frame generated here. No matter, what transforms
1371      * how transforms change size of the packet, it will come out.
1372      */
1373     skb->ignore_df = ip_sk_ignore_df(sk);
1374     
1375     /* DF bit is set when we want to see DF on outgoing frames.
1376      * If ignore_df is set too, we still allow to fragment this frame
1377      * locally. */
1378     if (inet->pmtudisc == IP_PMTUDISC_DO ||
1379         inet->pmtudisc == IP_PMTUDISC_PROBE ||
1380         (skb->len <= dst_mtu(&rt->dst) &&
1381          ip_dont_fragment(sk, &rt->dst)))
1382         df = htons(IP_DF);
1383 
1384     if (cork->flags & IPCORK_OPT)
1385         opt = cork->opt;
1386 
1387     if (cork->ttl != 0)
1388         ttl = cork->ttl;
1389     else if (rt->rt_type == RTN_MULTICAST)
1390         ttl = inet->mc_ttl;
1391     else
1392         ttl = ip_select_ttl(inet, &rt->dst);
1393 
1394     iph = ip_hdr(skb);
1395     iph->version = 4;
1396     iph->ihl = 5;
1397     iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
1398     iph->frag_off = df;
1399     iph->ttl = ttl;
1400     iph->protocol = sk->sk_protocol;
1401     ip_copy_addrs(iph, fl4);
1402     ip_select_ident(net, skb, sk);
1403 
1404     if (opt) {
1405         iph->ihl += opt->optlen>>2;
1406         ip_options_build(skb, opt, cork->addr, rt, 0);
1407     }
1408 
1409     skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
1410     skb->mark = sk->sk_mark;
1411     /*
1412      * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
1413      * on dst refcount
1414      */
1415     cork->dst = NULL;
1416     skb_dst_set(skb, &rt->dst);
1417 
1418     if (iph->protocol == IPPROTO_ICMP) {
1419         u8 icmp_type;
1420 
1421         /* For such sockets, transhdrlen is zero when do ip_append_data(),
1422          * so icmphdr does not in skb linear region and can not get icmp_type
1423          * by icmp_hdr(skb)->type.
1424          */
1425         if (sk->sk_type == SOCK_RAW && !inet_sk(sk)->hdrincl)
1426             icmp_type = fl4->fl4_icmp_type;
1427         else
1428             icmp_type = icmp_hdr(skb)->type;
1429         icmp_out_count(net, icmp_type);
1430     }
1431 
1432     ip_cork_release(cork);
1433 out:
1434     return skb;
1435 }
```

* 1350-1367: 清空临时send buffer, 将其它所有skb都放到一个skb的frag\_list中；

再来看\_\_ip\_append\_data():

```c
 868 static int __ip_append_data(struct sock *sk,   
 869                 struct flowi4 *fl4,            
 870                 struct sk_buff_head *queue,    
 871                 struct inet_cork *cork,        
 872                 struct page_frag *pfrag,       
 873                 int getfrag(void *from, char *to, int offset,
 874                     int len, int odd, struct sk_buff *skb),
 875                 void *from, int length, int transhdrlen,
 876                 unsigned int flags)                                                                                                                                                                    
 877 {                        
 878     struct inet_sock *inet = inet_sk(sk); 
 879     struct sk_buff *skb;
 880 
 881     struct ip_options *opt = cork->opt;
 882     int hh_len;
 883     int exthdrlen;
 884     int mtu;
 885     int copy;
 886     int err;
 887     int offset = 0;
 888     unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
 889     int csummode = CHECKSUM_NONE;  
 890     struct rtable *rt = (struct rtable *)cork->dst;                                                                                                                                                    
 891     u32 tskey = 0;
 892 
 893     skb = skb_peek_tail(queue);                                                                                                                                                                        
 894 
 895     exthdrlen = !skb ? rt->dst.header_len : 0;
 896     mtu = cork->fragsize;
 897     if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
 898         sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
 899         tskey = sk->sk_tskey++;                                                                                                                                                                        
 900 
 901     hh_len = LL_RESERVED_SPACE(rt->dst.dev);                                                                                                                                                           
 902 
 903     fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
 904     maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
 905     maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;                                                                                                                                               
 906 
 907     if (cork->length + length > maxnonfragsize - fragheaderlen) {
 908         ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
 909                    mtu - (opt ? opt->optlen : 0));
 910         return -EMSGSIZE;
 911     }
 912 
 913     /*
 914      * transhdrlen > 0 means that this is the first fragment and we wish
 915      * it won't be fragmented in the future.                                                                                                                                                           
 916      */
 917     if (transhdrlen &&
 918         length + fragheaderlen <= mtu &&
 919         rt->dst.dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&                                                                                                                                 
 920         !(flags & MSG_MORE) &&
 921         !exthdrlen)
 922         csummode = CHECKSUM_PARTIAL;                                                                                                                                                                   
 923 
 924     cork->length += length;
 925 
 926     /* So, what's going on in the loop below?                                                                                                                                                          
 927      *
 928      * We use calculated fragment length to generate chained skb,
 929      * each of segments is IP fragment ready for sending to network after                                                                                                                              
 930      * adding appropriate IP header.
 931      */
 932 
 933     if (!skb)
 934         goto alloc_new_skb;
 935 
 936     while (length > 0) {
 937         /* Check if the remaining data fits into current packet. */                                                                                                                                    
 938         copy = mtu - skb->len;
 939         if (copy < length)
 940             copy = maxfraglen - skb->len;
 941         if (copy <= 0) {
 942             char *data;
 943             unsigned int datalen;
 944             unsigned int fraglen;
 945             unsigned int fraggap;
 946             unsigned int alloclen;
 947             struct sk_buff *skb_prev;
 948 alloc_new_skb:
 949             skb_prev = skb;
 950             if (skb_prev)
 951                 fraggap = skb_prev->len - maxfraglen;
 952             else
 953                 fraggap = 0;
 954 
 955             /*
 956              * If remaining data exceeds the mtu,
 957              * we know we need more fragment(s).
 958              */
 959             datalen = length + fraggap;
 960             if (datalen > mtu - fragheaderlen)
 961                 datalen = maxfraglen - fragheaderlen;
 962             fraglen = datalen + fragheaderlen;
 963 
 964             if ((flags & MSG_MORE) &&
 965                 !(rt->dst.dev->features&NETIF_F_SG))
 966                 alloclen = mtu;
 967             else
 968                 alloclen = fraglen;
 969 
 970             alloclen += exthdrlen;
 971 
 972             /* The last fragment gets additional space at tail.
 973              * Note, with MSG_MORE we overallocate on fragments,
 974              * because we have no idea what fragment will be
 975              * the last.
 976              */
 977             if (datalen == length + fraggap)
 978                 alloclen += rt->dst.trailer_len;
 979 
 980             if (transhdrlen) {
 981                 skb = sock_alloc_send_skb(sk,
 982                         alloclen + hh_len + 15,
 983                         (flags & MSG_DONTWAIT), &err);
 984             } else {
 985                 skb = NULL;
 986                 if (refcount_read(&sk->sk_wmem_alloc) <=
 987                     2 * sk->sk_sndbuf)
 988                     skb = sock_wmalloc(sk,
 989                                alloclen + hh_len + 15, 1,
 990                                sk->sk_allocation);
 991                 if (unlikely(!skb))
 992                     err = -ENOBUFS;
 993             }
 994             if (!skb)
 995                 goto error;
 ...
1045             /*
1046              * Put the packet on the pending queue.
1047              */
1048             __skb_queue_tail(queue, skb);
1049             continue;
1050         }
1051 
1052         if (copy > length)
1053             copy = length;
1054 
1055         if (!(rt->dst.dev->features&NETIF_F_SG) &&
1056             skb_tailroom(skb) >= copy) {
1057             unsigned int off;
1058 
1059             off = skb->len;
1060             if (getfrag(from, skb_put(skb, copy),
1061                     offset, copy, off, skb) < 0) {
1062                 __skb_trim(skb, off);
1063                 err = -EFAULT;
1064                 goto error;
1065             }
1066         } else {
1067             int i = skb_shinfo(skb)->nr_frags;
1068 
1069             err = -ENOMEM;
1070             if (!sk_page_frag_refill(sk, pfrag))
1071                 goto error;
1072 
1073             if (!skb_can_coalesce(skb, i, pfrag->page,
1074                           pfrag->offset)) {
1075                 err = -EMSGSIZE;
1076                 if (i == MAX_SKB_FRAGS)
1077                     goto error;
1078 
1079                 __skb_fill_page_desc(skb, i, pfrag->page,
1080                              pfrag->offset, 0);
1081                 skb_shinfo(skb)->nr_frags = ++i;
1082                 get_page(pfrag->page);
1083             }
1084             copy = min_t(int, copy, pfrag->size - pfrag->offset);
1085             if (getfrag(from,
1086                     page_address(pfrag->page) + pfrag->offset,
1087                     offset, copy, skb->len, skb) < 0)
1088                 goto error_efault;
1089 
1090             pfrag->offset += copy;
1091             skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
1092             skb->len += copy;
1093             skb->data_len += copy;
1094             skb->truesize += copy;
1095             refcount_add(copy, &sk->sk_wmem_alloc);
1096         }
1097         offset += copy;
1098         length -= copy;
1099     }
1100 
1101     return 0;
```

981-983: UDP一定会调用sock\_alloc\_send\_skb()申请skb;

1095: copy的data长度需要记录到sk->sk\_wmem\_alloc中；

```c
2067 /*
2068  *  Generic send/receive buffer handlers
2069  */
2070 
2071 struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
2072                      unsigned long data_len, int noblock,
2073                      int *errcode, int max_page_order)
2074 {   
2075     struct sk_buff *skb;
2076     long timeo;
2077     int err;
2078     
2079     timeo = sock_sndtimeo(sk, noblock);
2080     for (;;) {
2081         err = sock_error(sk);
2082         if (err != 0)
2083             goto failure;
2084         
2085         err = -EPIPE;
2086         if (sk->sk_shutdown & SEND_SHUTDOWN)
2087             goto failure;
2088         
2089         if (sk_wmem_alloc_get(sk) < sk->sk_sndbuf)
2090             break;
2091         
2092         sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
2093         set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
2094         err = -EAGAIN;
2095         if (!timeo)
2096             goto failure;
2097         if (signal_pending(current))
2098             goto interrupted;
2099         timeo = sock_wait_for_wmem(sk, timeo);
2100     }
2101     skb = alloc_skb_with_frags(header_len, data_len, max_page_order,
2102                    errcode, sk->sk_allocation);
2103     if (skb)
2104         skb_set_owner_w(skb, sk);
2105     return skb;
2106 
2107 interrupted:
2108     err = sock_intr_errno(timeo);
2109 failure:
2110     *errcode = err;
2111     return NULL;
2112 }
2113 EXPORT_SYMBOL(sock_alloc_send_pskb);
2114             
2115 struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
2116                     int noblock, int *errcode)
2117 {           
2118     return sock_alloc_send_pskb(sk, size, 0, noblock, errcode, 0);
2119 }                       
```

2089-2090: 如果当前socket已经申请的写内存数量小于限制，则正常申请skb; sk\_wmem\_alloc\_get()返回的是sk->sk\_wmem\_alloc，即socket已经copy到kernel但尚未发送成功的数据长度；

2092-2099：否则如果超出的等待时间(no-blocking则不会等待)，就返回EAGAIN;

如果返回了EAGAIN, 只有相应的skb得到释放、send buffer有空间(即sk->sk\_wmem\_alloc减小)之后epoll才会返回EPOLLOUT。什么时候sk->sk\_wmem\_alloc才会减小呢？需要跟踪一下skb什么时候释放。

