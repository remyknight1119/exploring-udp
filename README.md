---
description: Based on Linux-4.14.316
---

# UDP sendto EAGAIN

&#x20;       使用TCP scoket发送数据的时候，内核会将用户态数据copy到TCP socket的send buffer中。如果调用send/sendmsg返回EAGAIN错误(sockfd需要设置为noblocking)，则意味着send buffer已满，需要暂停发送。TCP socket收到receiver发送的ACK并删除掉send buffer中已确认的data之后有了足够的空间后，epoll会返回EPOLLOUT event，这时用户态TCP socket就可以继续发送data了。

&#x20;       UDP协议是无连接的，用UDP sendto发送数据的时候也会出现EAGAIN错误吗？答案是：会出现。它是否有send buffer? 什么情况下才会通过epoll返回EPOLLOUT event通知user继续发送了呢？我们来看看linux kernel source code.

