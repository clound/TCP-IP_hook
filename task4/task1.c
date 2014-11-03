#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
unsigned char hextoascii(int achar)//16进制转换为ascii码值
{
	if(achar == 0xA)
		return 10;
	else if(achar == 0xD)
		return 13;
	else if(achar == 0x20)
		return 32;
	else if(achar >= 0x20 && achar <= 0x7E)
		return ' ' + (achar - 0x20);
	else
		return 	NULL;	
}
static unsigned int nf_hook_in(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int(*okfn)(struct sk_buff*))//钩子点输入
{
	struct sk_buff *sk = NULL;
	sk = skb_copy(skb,GFP_ATOMIC);
	struct iphdr *iph = ip_hdr(sk);//指向首地址
	struct tcphdr *tcph;
	tcph = (void*)iph + iph->ihl*4;//加入tcp部时（4字节）
	int i;
	int char_int1,cahr_int2;
	char char1 = NULL;
	char char2 = NULL;
	if(iph->protocol == IPPROTO_TCP)
	{
		if((tcph->source == htons(8080)||tcph->source == htons(80))&&((sk->len) >= 40)){//判断端口是否符合和数据空间是否大于40字节
			if(tcph->source == htons(8080)){
				printk("recv: This is 8080 package!\n");
				for(i = 40;i < sk->len;i++){
					char1 = hextoascii(*(sk->data+i));//取出其输出的16进制码并调用转换函数进行change
					printk("%c",char1);
				}			
				printk("\n");
			}
			else{			
				printk("recv: This is 80 package!\n");
				for(i = 40;i < sk->len;i++){
					char2 = hextoascii(*(sk->data+i));
					printk("%c",char2);			
				}
				printk("\n");
			}
		}
	}
	return NF_ACCEPT;
}
static unsigned int nf_hook_out(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int(*okfn)(struct sk_buff*))//钩子点输出
{
	struct sk_buff *sk = NULL;
	sk = skb_copy(skb,GFP_ATOMIC);
	struct iphdr *iph = ip_hdr(sk);
	struct tcphdr *tcph;
	tcph = (void*)iph + iph->ihl*4;
	int i;
	int char_int1,cahr_int2;
	char char1 = NULL;
	char char2 = NULL;
	if(iph->protocol == IPPROTO_TCP)
	{
		if((tcph->dest == htons(8080)||tcph->dest == htons(80))&&((sk->len) >= 40)){
			if(tcph->dest == htons(8080)){
				printk("send: This is 8080 package!\n");
				for(i = 40;i < sk->len;i++){
					char1 = hextoascii(*(sk->data+i));
					printk("%c",char1);			
				}				
				printk("\n");
			}
			else{
				printk("send: This is 80 package!\n");
				for(i = 40;i < sk->len;i++){
					char2 = hextoascii(*(sk->data+i));
					printk("%c",char2);
				}							
				printk("\n");			
			}
		}
	}
	return NF_ACCEPT;
}
static struct nf_hook_ops nfin=
{
	.hook = nf_hook_in,
	.hooknum = NF_INET_LOCAL_IN,//本地数据进入点
	.pf = PF_INET,
	.priority = 0
};
static struct nf_hook_ops nfout=
{
	.hook = nf_hook_out,
	.hooknum = NF_INET_LOCAL_OUT,//本地数据输出点
	.pf = PF_INET,
	.priority = 0
};
static int __init hello_init(void)
{	
	nf_register_hook(&nfin);//注册钩子点
	nf_register_hook(&nfout);
	printk("The register part is done!\n");
	return 0;
}
static void __exit hello_exit(void)
{
	nf_unregister_hook(&nfin);//注销钩子点
	nf_unregister_hook(&nfout);
	printk("The unregister part is done!\n");
}
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NETFILTER");
