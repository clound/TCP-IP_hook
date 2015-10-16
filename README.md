# TCP/IP hook
####TCP/IP的钩子函数
关键函数:
```
nf_register_hook(&nfin);//注册钩子点  
nf_register_hook(&nfout);  
nf_unregister_hook(&nfin);//注销钩子点  
nf_unregister_hook(&nfout);  
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
