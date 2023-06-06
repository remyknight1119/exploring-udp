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

1499: 初始化一个临时send buffer，仅用于这一次send；

1508-1510: 将用户态data copy到skb中并将skb放入到queue里；

1516: 将queue里面所有的skb都append到一个skb，并初始化IP header部分；

