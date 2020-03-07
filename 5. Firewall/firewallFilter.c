#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* This is the structure we shall use to register our function */ 
static struct nf_hook_ops outBoundFilterHook;
static struct nf_hook_ops inBoundFilterHook;
/* This is the hook function itself */
unsigned int outBoundPacketFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  
  unsigned int s1,s2,s3,s4; 
  unsigned int d1,d2,d3,d4;

  iph = ip_hdr(skb);
  tcph = (void *) iph+iph->ihl*4;

  s1 = ((unsigned char *)&iph->saddr)[0];
  s2 = ((unsigned char *)&iph->saddr)[1];
  s3 = ((unsigned char *)&iph->saddr)[2];
  s4 = ((unsigned char *)&iph->saddr)[3];

  d1 = ((unsigned char *)&iph->daddr)[0];
  d2 = ((unsigned char *)&iph->daddr)[1];
  d3 = ((unsigned char *)&iph->daddr)[2];
  d4 = ((unsigned char *)&iph->daddr)[3];

  printk(KERN_INFO "Checking for TCP packet to %d.%d.%d.%d\n",d1,d2,d3,d4);
   
   // Prevent TCP telnet connection with Machine B
   if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && d1==10 && d2==0 && d3==2 && d4==5)
   {
      printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
       ((unsigned char *)&iph->daddr) [0],
       ((unsigned char *)&iph->daddr) [1],
       ((unsigned char *)&iph->daddr) [2],
       ((unsigned char *)&iph->daddr) [3]
      );
      return NF_DROP;
   }// Prevent TCP SSH connection with Machine B
   else if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(22) && d1==10 && d2==0 && d3==2 && d4==5)
   {
      printk(KERN_INFO "Dropping SSH packet to %d.%d.%d.%d\n",
       ((unsigned char *)&iph->daddr) [0],
       ((unsigned char *)&iph->daddr) [1],
       ((unsigned char *)&iph->daddr) [2],
       ((unsigned char *)&iph->daddr) [3]
      );
      return NF_DROP;
   }// Prevent TCP HTTP/HHTPS connection with www.syr.edu
   else if(iph->protocol == IPPROTO_TCP && (tcph->dest == htons(80) || tcph->dest == htons(443))&& d1==128 && d2==230 && d3==18 && d4==198)
   {
      printk(KERN_INFO "Dropping HTTPS/HTTP packet to %d.%d.%d.%d\n",
       ((unsigned char *)&iph->daddr) [0],
       ((unsigned char *)&iph->daddr) [1],
       ((unsigned char *)&iph->daddr) [2],
       ((unsigned char *)&iph->daddr) [3]
      );
      return NF_DROP;
   }
   else
   {
      return NF_ACCEPT;
   }
   // Prevent TCP SSH connection with Machine B
   
}

unsigned int inBoundPacketFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  
  unsigned int s1,s2,s3,s4; 
  unsigned int d1,d2,d3,d4;

  iph = ip_hdr(skb);
  tcph = (void *) iph+iph->ihl*4;

  s1 = ((unsigned char *)&iph->saddr)[0];
  s2 = ((unsigned char *)&iph->saddr)[1];
  s3 = ((unsigned char *)&iph->saddr)[2];
  s4 = ((unsigned char *)&iph->saddr)[3];

  d1 = ((unsigned char *)&iph->daddr)[0];
  d2 = ((unsigned char *)&iph->daddr)[1];
  d3 = ((unsigned char *)&iph->daddr)[2];
  d4 = ((unsigned char *)&iph->daddr)[3];

  printk(KERN_INFO "Checking for TCP packet from %d.%d.%d.%d\n",s1,s2,s3,s4);
   
   // Prevent TCP telnet connection from Machine B
   if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && s1==10 && s2==0 && s3==2 && s4==5)
   {
      printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
       ((unsigned char *)&iph->daddr) [0],
       ((unsigned char *)&iph->daddr) [1],
       ((unsigned char *)&iph->daddr) [2],
       ((unsigned char *)&iph->daddr) [3]
      );
      return NF_DROP;
   }// Prevent TCP SSH connection from Machine B
   else if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(22) && s1==10 && s2==0 && s3==2 && s4==5)
   {
      printk(KERN_INFO "Dropping SSH packet from %d.%d.%d.%d\n",
       ((unsigned char *)&iph->daddr) [0],
       ((unsigned char *)&iph->daddr) [1],
       ((unsigned char *)&iph->daddr) [2],
       ((unsigned char *)&iph->daddr) [3]
      );
      return NF_DROP;
   }
   else
   {
      return NF_ACCEPT;
   }
   // Prevent TCP SSH connection from Machine B
   
}

/* Initialization routine */
int setUpFilter(void)
{ 
  printk(KERN_INFO "Placing OutBound Packet Filter.\n");
  outBoundFilterHook.hook = outBoundPacketFilter; /* Handler function */ 
  outBoundFilterHook.hooknum = NF_INET_POST_ROUTING; 
  outBoundFilterHook.pf = PF_INET;
  outBoundFilterHook.priority = NF_IP_PRI_FIRST; /* Make our function first */
  nf_register_hook(&outBoundFilterHook);

  printk(KERN_INFO "Placing InBound Packet Filter.\n");
  inBoundFilterHook.hook = inBoundPacketFilter; /* Handler function */ 
  inBoundFilterHook.hooknum = NF_INET_PRE_ROUTING; 
  inBoundFilterHook.pf = PF_INET;
  inBoundFilterHook.priority = NF_IP_PRI_FIRST; /* Make our function first */
  nf_register_hook(&inBoundFilterHook);

  return 0; 
}

/* Cleanup routine */ 
void removeFilter(void) 
{
  printk(KERN_INFO "Telnet filter removed.\n");
  nf_unregister_hook(&outBoundFilterHook); 
  nf_unregister_hook(&inBoundFilterHook); 
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");