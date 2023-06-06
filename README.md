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

2089-2090: 如果当前socket已经申请的写内存数量小于限制，则正常申请skb; sk\_wmem\_alloc\_get()返回的是sk->sk\_wmem\_alloc，即socket已经申请但尚未释放的skb的总内存大小；

2092-2099：否则如果超出的等待时间(no-blocking则不会等待)，就返回EAGAIN;

2103-2104: 将申请成功的skb的大小计入sk->sk\_wmem\_alloc中：

```c
1941 void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)                                                                                                                                             
1942 {
1943     skb_orphan(skb);     
1944     skb->sk = sk;        
1945 #ifdef CONFIG_INET       
1946     if (unlikely(!sk_fullsock(sk))) {  
1947         skb->destructor = sock_edemux; 
1948         sock_hold(sk);   
1949         return;          
1950     }
1951 #endif
1952     skb->destructor = sock_wfree;  
1953     skb_set_hash_from_sk(skb, sk); 
1954     /*
1955      * We used to take a refcount on sk, but following operation
1956      * is enough to guarantee sk_free() wont free this sock until
1957      * all in-flight packets are completed                                                                                                                                                             
1958      */
1959     refcount_add(skb->truesize, &sk->sk_wmem_alloc);                                                                                                                                                   
1960 }
```

&#x20;       如果sock\_alloc\_send\_pskb返回了EAGAIN, 只有相应的skb得到释放、send buffer有空间(即sk->sk\_wmem\_alloc减小)之后epoll才会返回EPOLLOUT。什么时候sk->sk\_wmem\_alloc才会减小呢？需要跟踪一下skb什么时候释放。

```c
870 int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)                                                                                                                                       
871 {
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
```

&#x20;   udp\_sendmsg()在调用ip\_make\_skb()申请完毕skb之后，会调用udp\_send\_skb()将skb发送出去；udp\_send\_skb()最终会调到\_\_netdev\_start\_xmit()(<mark style="color:blue;">**udp\_send\_skb()-->ip\_send\_skb()-->ip\_local\_out()-->\_\_ip\_local\_out()-->dst\_output()-->ip\_output()-->ip\_finish\_output()-->ip\_finish\_output2()-->neigh\_output()-->dev\_queue\_xmit()-->\_\_dev\_queue\_xmit()-->\_\_dev\_xmit\_skb()-->sch\_direct\_xmit()-->dev\_hard\_start\_xmit()-->xmit\_one()-->netdev\_start\_xmit()-->\_\_netdev\_start\_xmit()**</mark>):

```c
4051 static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
4052                           struct sk_buff *skb, struct net_device *dev,                                                                                                               
4053                           bool more)                                                                                                                                                 
4054 {
4055     skb->xmit_more = more ? 1 : 0; 
4056     return ops->ndo_start_xmit(skb, dev);                                                                                                                                            
4057 }
```

&#x20;   ops->ndo\_start\_xmit指向的是网卡driver的相应函数；以vmxnet3网卡为例，这个指针指向的就是vmxnet3\_xmit\_frame()：

```c
3235 static int
3236 vmxnet3_probe_device(struct pci_dev *pdev,
3237              const struct pci_device_id *id)
3238 {                       
3239     static const struct net_device_ops vmxnet3_netdev_ops = {
3240         .ndo_open = vmxnet3_open,
3241         .ndo_stop = vmxnet3_close,
3242         .ndo_start_xmit = vmxnet3_xmit_frame,
3243         .ndo_set_mac_address = vmxnet3_set_mac_addr,
3244         .ndo_change_mtu = vmxnet3_change_mtu,
3245         .ndo_set_features = vmxnet3_set_features,
3246         .ndo_get_stats64 = vmxnet3_get_stats64,
3247         .ndo_tx_timeout = vmxnet3_tx_timeout,
3248         .ndo_set_rx_mode = vmxnet3_set_mc,
3249         .ndo_vlan_rx_add_vid = vmxnet3_vlan_rx_add_vid,
3250         .ndo_vlan_rx_kill_vid = vmxnet3_vlan_rx_kill_vid,
3251 #ifdef CONFIG_NET_POLL_CONTROLLER
3252         .ndo_poll_controller = vmxnet3_netpoll,
3253 #endif           
3254     };
...
```

```c
1152 static netdev_tx_t
1153 vmxnet3_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
1154 {
1155     struct vmxnet3_adapter *adapter = netdev_priv(netdev);
1156 
1157     BUG_ON(skb->queue_mapping > adapter->num_tx_queues);
1158     return vmxnet3_tq_xmit(skb,
1159                    &adapter->tx_queue[skb->queue_mapping],
1160                    adapter, netdev);
1161 }
1162 
```

```c
 968 /*
 969  * Transmits a pkt thru a given tq
 970  * Returns:
 971  *    NETDEV_TX_OK:      descriptors are setup successfully
 972  *    NETDEV_TX_OK:      error occurred, the pkt is dropped
 973  *    NETDEV_TX_BUSY:    tx ring is full, queue is stopped
 974  *
 975  * Side-effects:
 976  *    1. tx ring may be changed
 977  *    2. tq stats may be updated accordingly
 978  *    3. shared->txNumDeferred may be updated
 979  */
 980 
 981 static int
 982 vmxnet3_tq_xmit(struct sk_buff *skb, struct vmxnet3_tx_queue *tq,
 983         struct vmxnet3_adapter *adapter, struct net_device *netdev)
 984 {
 985     int ret;
 986     u32 count;
 987     unsigned long flags;
 988     struct vmxnet3_tx_ctx ctx;
 989     union Vmxnet3_GenericDesc *gdesc;
 990 #ifdef __BIG_ENDIAN_BITFIELD
 991     /* Use temporary descriptor to avoid touching bits multiple times */
 992     union Vmxnet3_GenericDesc tempTxDesc;
 993 #endif
 ...
1070     /* fill tx descs related to addr & len */
1071     if (vmxnet3_map_pkt(skb, &ctx, tq, adapter->pdev, adapter))
1072         goto unlock_drop_pkt;
...
```

* 1070: vmxnet3\_map\_pkt()函数将skb map到网卡的内存区；

```c
 676 static int
 677 vmxnet3_map_pkt(struct sk_buff *skb, struct vmxnet3_tx_ctx *ctx,
 678         struct vmxnet3_tx_queue *tq, struct pci_dev *pdev,
 679         struct vmxnet3_adapter *adapter)
 680 {
 681     u32 dw2, len;
 682     unsigned long buf_offset;
 683     int i;
 684     union Vmxnet3_GenericDesc *gdesc;
 685     struct vmxnet3_tx_buf_info *tbi = NULL;
 686 
 687     BUG_ON(ctx->copy_size > skb_headlen(skb));
 688 
 689     /* use the previous gen bit for the SOP desc */
 690     dw2 = (tq->tx_ring.gen ^ 0x1) << VMXNET3_TXD_GEN_SHIFT;
 691 
 692     ctx->sop_txd = tq->tx_ring.base + tq->tx_ring.next2fill;
 693     gdesc = ctx->sop_txd; /* both loops below can be skipped */
 694 
 695     /* no need to map the buffer if headers are copied */
 696     if (ctx->copy_size) {
 697         ctx->sop_txd->txd.addr = cpu_to_le64(tq->data_ring.basePA +
 698                     tq->tx_ring.next2fill *
 699                     tq->txdata_desc_size);
 700         ctx->sop_txd->dword[2] = cpu_to_le32(dw2 | ctx->copy_size);
 701         ctx->sop_txd->dword[3] = 0;
 702         
 703         tbi = tq->buf_info + tq->tx_ring.next2fill;
 704         tbi->map_type = VMXNET3_MAP_NONE;
 705         
 706         netdev_dbg(adapter->netdev,
 707             "txd[%u]: 0x%Lx 0x%x 0x%x\n",
 708             tq->tx_ring.next2fill,
 709             le64_to_cpu(ctx->sop_txd->txd.addr),
 710             ctx->sop_txd->dword[2], ctx->sop_txd->dword[3]);
 711         vmxnet3_cmd_ring_adv_next2fill(&tq->tx_ring);
 712         
 713         /* use the right gen for non-SOP desc */
 714         dw2 = tq->tx_ring.gen << VMXNET3_TXD_GEN_SHIFT;
 715     }
 716 
 717     /* linear part can use multiple tx desc if it's big */
 718     len = skb_headlen(skb) - ctx->copy_size;
 719     buf_offset = ctx->copy_size;
 720     while (len) {
 721         u32 buf_size;
 722 
 723         if (len < VMXNET3_MAX_TX_BUF_SIZE) {
 724             buf_size = len;
 725             dw2 |= len;
 726         } else {
 727             buf_size = VMXNET3_MAX_TX_BUF_SIZE;
 728             /* spec says that for TxDesc.len, 0 == 2^14 */
 729         }
 730 
 731         tbi = tq->buf_info + tq->tx_ring.next2fill;
 732         tbi->map_type = VMXNET3_MAP_SINGLE;
 733         tbi->dma_addr = dma_map_single(&adapter->pdev->dev,
 734                 skb->data + buf_offset, buf_size,
 735                 PCI_DMA_TODEVICE);
 736         if (dma_mapping_error(&adapter->pdev->dev, tbi->dma_addr))
 737             return -EFAULT;
 738 
 739         tbi->len = buf_size;
 740 
 741         gdesc = tq->tx_ring.base + tq->tx_ring.next2fill;
 742         BUG_ON(gdesc->txd.gen == tq->tx_ring.gen);
 743 
 744         gdesc->txd.addr = cpu_to_le64(tbi->dma_addr);
 745         gdesc->dword[2] = cpu_to_le32(dw2);
 746         gdesc->dword[3] = 0;
 747 
 748         netdev_dbg(adapter->netdev,
 749             "txd[%u]: 0x%Lx 0x%x 0x%x\n",
 750             tq->tx_ring.next2fill, le64_to_cpu(gdesc->txd.addr),
 751             le32_to_cpu(gdesc->dword[2]), gdesc->dword[3]);
 752         vmxnet3_cmd_ring_adv_next2fill(&tq->tx_ring);
 753         dw2 = tq->tx_ring.gen << VMXNET3_TXD_GEN_SHIFT;
 754 
 755         len -= buf_size;
 756         buf_offset += buf_size;
 757     }
 758 
 759     for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
 760         const struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[i];
 761         u32 buf_size;
 762 
 763         buf_offset = 0;
 764         len = skb_frag_size(frag);
 765         while (len) {
 766             tbi = tq->buf_info + tq->tx_ring.next2fill;
 767             if (len < VMXNET3_MAX_TX_BUF_SIZE) {
 768                 buf_size = len;
 769                 dw2 |= len;
 770             } else {
 771                 buf_size = VMXNET3_MAX_TX_BUF_SIZE;
 772                 /* spec says that for TxDesc.len, 0 == 2^14 */
 773             }
 774             tbi->map_type = VMXNET3_MAP_PAGE;
 775             tbi->dma_addr = skb_frag_dma_map(&adapter->pdev->dev, frag,
 776                              buf_offset, buf_size,
 777                              DMA_TO_DEVICE);
 778             if (dma_mapping_error(&adapter->pdev->dev, tbi->dma_addr))
 779                 return -EFAULT;
 780 
 781             tbi->len = buf_size;
 782 
 783             gdesc = tq->tx_ring.base + tq->tx_ring.next2fill;
 784             BUG_ON(gdesc->txd.gen == tq->tx_ring.gen);
 785 
 786             gdesc->txd.addr = cpu_to_le64(tbi->dma_addr);
 787             gdesc->dword[2] = cpu_to_le32(dw2);
 788             gdesc->dword[3] = 0;
 789 
 790             netdev_dbg(adapter->netdev,
 791                 "txd[%u]: 0x%llx %u %u\n",
 792                 tq->tx_ring.next2fill, le64_to_cpu(gdesc->txd.addr),
 793                 le32_to_cpu(gdesc->dword[2]), gdesc->dword[3]);
 794             vmxnet3_cmd_ring_adv_next2fill(&tq->tx_ring);
 795             dw2 = tq->tx_ring.gen << VMXNET3_TXD_GEN_SHIFT;
 796 
 797             len -= buf_size;
 798             buf_offset += buf_size;
 799         }
 800     }
 801 
 802     ctx->eop_txd = gdesc;
 803 
 804     /* set the last buf_info for the pkt */
 805     tbi->skb = skb;
 806     tbi->sop_idx = ctx->sop_txd - tq->tx_ring.base;
 807 
 808     return 0;
 809 }
```

* 805: skb被挂在了tbi->skb指针上，tbi来自struct vmxnet3\_tx\_queue的buf\_info ring;

当skb的数据被网卡发送到网络中后，(可能是)软中断上下文会调用vmxnet3\_tq\_tx\_complete()函数来释放skb:

```c
 363 static int
 364 vmxnet3_tq_tx_complete(struct vmxnet3_tx_queue *tq,
 365             struct vmxnet3_adapter *adapter)
 366 {
 367     int completed = 0;
 368     union Vmxnet3_GenericDesc *gdesc;
 369 
 370     gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;
 371     while (VMXNET3_TCD_GET_GEN(&gdesc->tcd) == tq->comp_ring.gen) {
 372         /* Prevent any &gdesc->tcd field from being (speculatively)
 373          * read before (&gdesc->tcd)->gen is read.
 374          */
 375         dma_rmb();
 376 
 377         completed += vmxnet3_unmap_pkt(VMXNET3_TCD_GET_TXIDX(
 378                            &gdesc->tcd), tq, adapter->pdev,
 379                            adapter);
 380 
 381         vmxnet3_comp_ring_adv_next2proc(&tq->comp_ring);
 382         gdesc = tq->comp_ring.base + tq->comp_ring.next2proc;
 383     }
 384 
 385     if (completed) {
 386         spin_lock(&tq->tx_lock);
 387         if (unlikely(vmxnet3_tq_stopped(tq, adapter) &&
 388                  vmxnet3_cmd_ring_desc_avail(&tq->tx_ring) >
 389                  VMXNET3_WAKE_QUEUE_THRESHOLD(tq) &&
 390                  netif_carrier_ok(adapter->netdev))) {
 391             vmxnet3_tq_wake(tq, adapter);
 392         }
 393         spin_unlock(&tq->tx_lock);
 394     }
 395     return completed;
 396 }
```

* 377: vmxnet3\_unmap\_pkt()会free vmxnet3\_tx\_queue的buf\_info ring上的skb;

```c
 329 vmxnet3_unmap_pkt(u32 eop_idx, struct vmxnet3_tx_queue *tq,
 330           struct pci_dev *pdev, struct vmxnet3_adapter *adapter)
 331 {
 332     struct sk_buff *skb;
 333     int entries = 0;
 334 
 335     /* no out of order completion */
 336     BUG_ON(tq->buf_info[eop_idx].sop_idx != tq->tx_ring.next2comp);
 337     BUG_ON(VMXNET3_TXDESC_GET_EOP(&(tq->tx_ring.base[eop_idx].txd)) != 1);
 338 
 339     skb = tq->buf_info[eop_idx].skb;
 340     BUG_ON(skb == NULL);
 341     tq->buf_info[eop_idx].skb = NULL;
 342 
 343     VMXNET3_INC_RING_IDX_ONLY(eop_idx, tq->tx_ring.size);
 344 
 345     while (tq->tx_ring.next2comp != eop_idx) {
 346         vmxnet3_unmap_tx_buf(tq->buf_info + tq->tx_ring.next2comp,
 347                      pdev);
 348 
 349         /* update next2comp w/o tx_lock. Since we are marking more,
 350          * instead of less, tx ring entries avail, the worst case is
 351          * that the tx routine incorrectly re-queues a pkt due to
 352          * insufficient tx ring entries.
 353          */
 354         vmxnet3_cmd_ring_adv_next2comp(&tq->tx_ring);
 355         entries++;
 356     }
 357 
 358     dev_kfree_skb_any(skb);
 359     return entries;
 360 }
```

* 358: dev\_kfree\_skb\_any()释放skb;

```c
3282 static inline void dev_kfree_skb_any(struct sk_buff *skb)
3283 {
3284     __dev_kfree_skb_any(skb, SKB_REASON_DROPPED);
3285 } 
```

```c
2526 void __dev_kfree_skb_any(struct sk_buff *skb, enum skb_free_reason reason)
2527 {
2528     if (in_irq() || irqs_disabled())
2529         __dev_kfree_skb_irq(skb, reason);
2530     else if (unlikely(reason == SKB_REASON_DROPPED))
2531         kfree_skb(skb);
2532     else
2533         consume_skb(skb);
2534 }
```

```c
 666 void kfree_skb(struct sk_buff *skb)
 667 {
 668     if (!skb_unref(skb))
 669         return;
 670 
 671     trace_kfree_skb(skb, __builtin_return_address(0));
 672     __kfree_skb(skb);
 673 }
```

```c
 652 void __kfree_skb(struct sk_buff *skb)
 653 {
 654     skb_release_all(skb);
 655     kfree_skbmem(skb);
 656 }
```

```c
 636 static void skb_release_all(struct sk_buff *skb)
 637 {
 638     skb_release_head_state(skb);
 639     if (likely(skb->head))
 640         skb_release_data(skb);
 641 }
```

```c
 619 void skb_release_head_state(struct sk_buff *skb)
 620 {
 621     skb_dst_drop(skb);
 622     secpath_reset(skb);
 623     if (skb->destructor) {
 624         WARN_ON(in_irq());
 625         skb->destructor(skb);
 626     }
 627 #if IS_ENABLED(CONFIG_NF_CONNTRACK)
 628     nf_conntrack_put(skb_nfct(skb));
 629 #endif
 630 #if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
 631     nf_bridge_put(skb->nf_bridge);
 632 #endif
 633 }c
```

