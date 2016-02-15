#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bc. Tomas Kubovcik");

#define FILE_NAME "pdsfw"   //module name as it appears under /proc
#define MAX_SIZE 4096       //procfs buffer size

static unsigned long procBuffSize = 0; // size of the data held in the buffer
static struct proc_dir_entry *proc; // refer http://docs.huihoo.com/doxygen/linux/kernel/3.7/structproc__dir__entry.html
static struct nf_hook_ops nfho;

char            *procf_buffer;
unsigned long    procf_buffer_pos = 0;
static struct    pdsfw_rule pdsfw_rule_list;

//
//  Structure for firewall policies
//  - decoded from user space
//
struct pdsfw_rule_d
{
    char*           id;         //incoming id as string f.e. [127\0]
    unsigned char   action;     //'d' to block packet, 'a' to let it pass
    char*           src_ip;     //standard ipv4 format without mask
    char*           src_port;
    char*           dst_ip;
    char*           dst_port;
    unsigned char   protocol;   //'t' - TCP, 'u' - UDP, 'm' - ICMP, 'i' - IP
};

//
//  Structure for firewall policies
//  -   internal format
//
struct pdsfw_rule
{
    unsigned int  id;
    unsigned char action;
    unsigned int  src_ip;
    unsigned int  src_port;
    unsigned int  dst_ip;
    unsigned int  dst_port;
    unsigned char protocol;

    struct list_head list;
};

//
//  Convertors from string to int
//
// -----------------------------------------------------------------------------------------
//PORT and ID 
unsigned int portToInt(char *port_str)
{
    unsigned int port = 0;    

    int i = 0;
    
    //Invalid string
    if (port_str == NULL)
        return 0;

    while (port_str[i] != '\0')
    {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }

    return port;
}

//IP to unsigned int
unsigned int IPtoInt(char *ip_str)
{
    unsigned char ip_array[4];  //array to store ip octants
    
    unsigned int ip = 0;        //var to store final ip
    unsigned int ip_index = 0;  //index in input string
    unsigned int i;             //octant index
    
    //Empty string
    if (ip_str == NULL)
        return 0; 

    memset(ip_array, 0, 4);

    //Process 3 octants of IP
    for(i = 0; i < 3; i++)
    {
        while (ip_str[ip_index] != '.')
            ip_array[i] = ip_array[i]*10 + (ip_str[ip_index++] - '0');
        
        ++ip_index;
    }

    //Process last octant
    while (ip_str[ip_index] != '\0')
        ip_array[3] = ip_array[3]*10 + (ip_str[ip_index++] - '0');

    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);

    return ip;
}
// -----------------------------------------------------------------------------------------

//
//  Convertors from int to string
//
void IPtoString(unsigned int ip, char *ip_str)
{
    unsigned char ip_array[4];

    memset(ip_array, 0, 4);
    
    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

//PORT
void portToString(unsigned int port, char *port_str)
{
    sprintf(port_str, "%u", port);
}
// -----------------------------------------------------------------------------------------

//
//  Sequence file
//
static void *seq_start(struct seq_file *s, loff_t *pos)
{
    return seq_list_start(&(pdsfw_rule_list.list), *pos);
}

static void *seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &(pdsfw_rule_list.list), pos);
}

static void seq_stop(struct seq_file *s, void *v)
{
    // empty for the example... I couldn't figure out what to do here.
}

static int seq_show(struct seq_file *s, void *v)
{
    //print whatever is iterated
    struct pdsfw_rule *rule = list_entry(v, struct pdsfw_rule, list);

    if(rule != NULL)
    {
        char action[10];
        char protocol[10];
        char src_ip[20];
        char src_port[10];
        char dst_ip[20];
        char dst_port[10];    

        if(rule->action == 'a')
            strcpy(action, "allow");
        else
            strcpy(action, "deny");

        if (rule->src_ip == 0)
            strcpy(src_ip, "*");
        else
            IPtoString(rule->src_ip, src_ip);

        //get src port
        if (rule->src_port == 0)
            strcpy(src_port, "*");
        else
            portToString(rule->src_port, src_port);

        //get dst IP
        if (rule->dst_ip == 0)
            strcpy(dst_ip, "*");
        else
            IPtoString(rule->dst_ip, dst_ip);

        //get dst port
        if (rule->dst_port == 0)
            strcpy(dst_port, "*");
        else
            portToString(rule->dst_port, dst_port);

        if (rule->protocol == 't')
            strcpy(protocol, "tcp");
        else if (rule->protocol == 'u')
            strcpy(protocol, "udp");
        else if (rule->protocol == 'm')
            strcpy(protocol, "icmp");
        else if (rule->protocol == 'i')
            strcpy(protocol, "ip");

        //memcpy(procf_buffer + procf_buffer_pos, "$\n", 2);

        seq_printf(s, "%d\t%s\t%s\t\t%s\t%s\t\t%s\t%s\n", rule->id, action, src_ip, src_port, dst_ip, dst_port, protocol);

        return 0;
    }

    return 1;
}
//--------------------------------------------------------------------------------------------------

//
//  Checks whether loaded rule is already part of loaded rules
//
bool CheckDuplicity(struct pdsfw_rule* rule)
{
    struct pdsfw_rule* tmp;
    unsigned int i;

    printk(KERN_INFO "Duplicity rule check:");

    list_for_each_entry(tmp, &pdsfw_rule_list.list, list)
    {
        printk(KERN_INFO "%u : %u\n", tmp->id, rule->id);

        i = 0;

            if(tmp->id == rule->id)
                i++;
            if(tmp->action == rule->action)
                i++;
            if(tmp->src_ip == rule->src_ip)
                i++;
            if(tmp->src_port == rule->src_port)
                i++;
            if(tmp->dst_ip == rule->dst_ip)
                i++;
            if(tmp->dst_port == rule->dst_port)
                i++;
            if(tmp->protocol == rule->protocol)
                i++;

            if(i == 7)
                return true;
    }

    return false;
}

//
//  Checks if new rule id already exists and if does update it
//
bool CheckID(struct pdsfw_rule* rule)
{
    struct pdsfw_rule* tmp;

    printk(KERN_INFO "Duplicity rule check:");

    list_for_each_entry(tmp, &pdsfw_rule_list.list, list)
    {
        if(tmp->id == rule->id)
        {
            tmp->action = rule->action;
            tmp->src_ip = rule->src_ip;
            tmp->src_port = rule->src_port;
            tmp->dst_ip = rule->dst_ip;
            tmp->dst_port = rule->dst_port;
            tmp->protocol = rule->protocol;

            return true;
        }
    }

    return false;
}

//
//  Adds firewall rule to list
//
void AddFirewallRule(struct pdsfw_rule_d* rd)
{
    struct pdsfw_rule* curr;
    struct pdsfw_rule* prev;

    int min = 0;

    //allocate memory for new rule
    struct pdsfw_rule* rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if(rule == NULL)
    {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }    

    //id, action, protocol are required and we trust client did its job sending valid data
    rule->id        = portToInt(rd->id);
    rule->action    = rd->action;
    rule->protocol  = rd->protocol;

    //store source ip
    if (strcmp(rd->src_ip, "any") == 0) 
        rule->src_ip = 0;
    else
        rule->src_ip = IPtoInt(rd->src_ip);

    //store source port
    if (strcmp(rd->src_port,"*") == 0)
            rule->src_port = 0;
    else
        rule->src_port = portToInt(rd->src_port);

    //store destination ip
    if (strcmp(rd->dst_ip, "any") == 0) 
        rule->dst_ip = 0;
    else
        rule->dst_ip = IPtoInt(rd->dst_ip);        

    //store destination port
    if (strcmp(rd->dst_port, "*") == 0)
            rule->dst_port = 0;
    else
        rule->dst_port = portToInt(rd->dst_port);

    if(CheckDuplicity(rule) == true)
    {
        printk(KERN_INFO "Duplicated rule");
        kfree(rule);
        return;
    }
    
    if(CheckID(rule) == false)
    {
        printk(KERN_INFO "Add rule: id=%d, action=%c src_ip=%u, src_port=%u, dest_ip=%u, dest_port=%u, protocol=%c\n", rule->id, rule->action, rule->src_ip, rule->src_port, rule->dst_ip, rule->dst_port, rule->protocol);    
        INIT_LIST_HEAD(&(rule->list));

        list_for_each_entry(curr, &pdsfw_rule_list.list, list)
        {
            if(curr->id < rule->id)
            {
                //store pointer to current
                prev = curr;
                min++;
                continue;
            }
            else
            {
                //add after head
                if(min == 0)
                    list_add(&(rule->list), &(pdsfw_rule_list.list));
                else
                    //add between prev and curr
                    __list_add(&(rule->list), &(prev->list), &(curr->list));    
                
                return;
            }
        }

        //add to tail
        list_add_tail(&(rule->list), &(pdsfw_rule_list.list));
    }
}

//
//  Init rule structure
//
void InitPdsfwRuleD(struct pdsfw_rule_d* rd)
{
    rd->id = (char*)kmalloc(4, GFP_KERNEL);
    rd->action = 0;
    rd->src_ip = (char*)kmalloc(16, GFP_KERNEL);
    rd->src_port = (char*)kmalloc(16, GFP_KERNEL);
    rd->dst_ip = (char*)kmalloc(16, GFP_KERNEL);
    rd->dst_port = (char*)kmalloc(16, GFP_KERNEL);
    rd->protocol = 0;
}

//
//  Delete rule
//
void DeleteRule(int num)
{
    struct list_head *p, *q;
    struct pdsfw_rule *rule;

    list_for_each_safe(p, q, &pdsfw_rule_list.list)
    {
        rule = list_entry(p, struct pdsfw_rule, list);
            
        if(rule->id == num)
        {
            //delete and free
            list_del(p);
            kfree(rule);

            printk(KERN_INFO "Removing rule %d: SUCCESS\n", num);
            return;
        }
    }

    printk(KERN_INFO "FAILED [rule id not found]\n");
}


/*static ssize_t procRead(struct file *fp, char *buffer, size_t len, loff_t *offset)
{
    // --------------------
    int ret;

    struct pdsfw_rule* rule;
    char value[25];

    procf_buffer_pos = 0;
    ret = 0;

    //iterate over rule list
    list_for_each_entry(rule, &pdsfw_rule_list.list, list)
    {
        portToString(rule->id, value);

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t", 1);
        procf_buffer_pos++;

        if(rule->action == 'a')
            strcpy(value, "allow");
        else
            strcpy(value, "deny");

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t", 1);
        procf_buffer_pos++;

        //get src IP
        if (rule->src_ip == 0)
            strcpy(value, "*");
        else
            IPtoString(rule->src_ip, value);

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t\t", 2);
        procf_buffer_pos += 2;

        //get src port
        if (rule->src_port == 0)
            strcpy(value, "*");
        else
            portToString(rule->src_port, value);

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t", 1);
        procf_buffer_pos++;

        //get dst IP
        if (rule->dst_ip == 0)
            strcpy(value, "*");
        else
            IPtoString(rule->dst_ip, value);

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t\t", 2);
        procf_buffer_pos += 2;

        //get dst port
        if (rule->dst_port == 0)
            strcpy(value, "*");
        else
            portToString(rule->dst_port, value);

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\t", 1);
        procf_buffer_pos++;

        //get protocol
        if (rule->protocol == 't')
            strcpy(value, "tcp");
        else if (rule->protocol == 'u')
            strcpy(value, "udp");
        else if (rule->protocol == 'm')
            strcpy(value, "icmp");
        else if (rule->protocol == 'i')
            strcpy(value, "ip");

        memcpy(procf_buffer + procf_buffer_pos, value, strlen(value));
        procf_buffer_pos += strlen(value);
        memcpy(procf_buffer + procf_buffer_pos, "\n", 1);
        procf_buffer_pos++;
    }
    //---------------------

    memcpy(procf_buffer + procf_buffer_pos, "$\n", 2);
    procf_buffer_pos += 2;

    if(copy_to_user(buffer, procf_buffer, procf_buffer_pos))
        return -EFAULT;

    printk(KERN_INFO "read %lu bytes\n", procf_buffer_pos);

    return procf_buffer_pos;
    //return simple_read_from_buffer(buffer, procf_buffer_pos, offset, procf_buffer, MAX_SIZE);
}*/

static ssize_t procWrite(struct file *fp, const char *userBuf, size_t count, loff_t *off)
{
    int i, j;
    struct pdsfw_rule_d* rd;

    printk(KERN_INFO "procf_write is called.\n");

    procf_buffer_pos = 0;

    printk(KERN_INFO "pos: %ld; count: %ld\n", procf_buffer_pos, count);

    if(procf_buffer_pos + count > MAX_SIZE)
       count = MAX_SIZE-procf_buffer_pos;

    if(copy_from_user(procf_buffer+procf_buffer_pos, userBuf, count))
        return -EFAULT;

    rd = kmalloc(sizeof(*rd), GFP_KERNEL);
    if(rd == NULL)
    {
        printk(KERN_INFO "Error: Cannot allocate memory for firewall rule!");

        return -ENOMEM;
    }

    InitPdsfwRuleD(rd);

    i = procf_buffer_pos;

    //Handle Delete Rule command    
    if(procf_buffer[i] == 'd')
    {
        j = 0;
        
        while(procf_buffer[++i] != '\n')
           j = j*10 + (procf_buffer[i]-'0'); 

       DeleteRule(j);
       return count;
    }

    //fill id
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->id[j++]  = procf_buffer[i++];
    
    i++;
    rd->id[j] = '\0';

    //fill action
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->action = (procf_buffer[i++]);

    i++;

    //fill src_ip
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->src_ip[j++] = procf_buffer[i++];

    i++;
    rd->src_ip[j] = '\0';

    //fill src_port
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->src_port[j++] = procf_buffer[i++];

    i++;
    rd->src_port[j] = '\0';

    //fill dst_ip
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->dst_ip[j++] = procf_buffer[i++];

    i++;
    rd->dst_ip[j] = '\0';

    //fill dst_port
    j = 0;
    while(procf_buffer[i] != '\t')
        rd->dst_port[j++] = procf_buffer[i++];

    i++;
    rd->dst_port[j] = '\0';

    //fill protocol
    j = 0;
 
    if (procf_buffer[i] != '\t')
       rd->protocol = procf_buffer[i++];

    i++;

    AddFirewallRule(rd);
    kfree(rd);

    printk(KERN_INFO "Wrote %lu bytes from /proc/%s\n", count, FILE_NAME);
    procBuffSize += count;

  return count;
}

int procOpen(struct inode *inode, struct file *fp)
{
    try_module_get(THIS_MODULE);
    return 0;
}

int procClose(struct inode *inode, struct file *fp)
{
    module_put(THIS_MODULE);
    return 0;
}

/*static struct file_operations procFops =
{
    read: procRead,
    write: procWrite,
    open: procOpen,
    release: procClose,
};*/

static struct seq_operations seq_ops =
{
    start: seq_start,
    next: seq_next,
    stop: seq_stop,
    show: seq_show,
};

static int my_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &seq_ops);
}

/* read, lseek and release are defined by the seq file interface */
static struct file_operations fops =
{
    open: my_open,
    owner: THIS_MODULE,
    read: seq_read,
    llseek: seq_lseek,
    release: seq_release,
    write: procWrite,
};
//-------------------------------------------------------------------------------


//
//  Check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared
//
bool CheckIP(unsigned int ip, unsigned int ip_rule)
{
    unsigned int tmp = ntohl(ip);

    if (tmp != ip_rule)
    {
        printk(KERN_INFO "Compared IP: %u <=> %u: Doesn't match\n", tmp, ip_rule);
        return false;
    }

    printk(KERN_INFO "Compare IP: %u <=> %u: Match\n", tmp, ip_rule);
    return true;
}

//
//  Hook function: filtering incoming packets
// 
unsigned int hook_func_in(  unsigned int hooknum, struct sk_buff *skb,
                            const struct net_device *in, const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
   //get src ip, src port, dest ip, dst port, protocol
   struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;

   struct list_head *p;
   
   struct pdsfw_rule *rule;
   
   char src_ip_str[16];
   char dest_ip_str[16];
 
   //get src and dest ip addresses
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
 
   //get src and dest port number
   //udp
   if (ip_header->protocol == 17)
   {
       udp_header = (struct udphdr*)((__u32 *)ip_header + ip_header->ihl);
       src_port = htons((unsigned short int)udp_header->source);
       dest_port = htons((unsigned short int)udp_header->dest);
   }
   //tcp
   else if (ip_header->protocol == 6)
   {
       tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
       src_port = htons((unsigned short int)tcp_header->source);
       dest_port = htons((unsigned short int)tcp_header->dest);
   }
   //we do not need ports for icmp/ip

   IPtoString(ntohl(src_ip), src_ip_str);
   IPtoString(ntohl(dest_ip), dest_ip_str);
 
   printk(KERN_INFO "IN packet info: src ip: %u = %s, src port: %u; dest ip: %u = %s, dest port: %u; proto: %u\n", src_ip, src_ip_str, src_port, dest_ip, dest_ip_str, dest_port, ip_header->protocol); 
 
   //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one
   list_for_each(p, &pdsfw_rule_list.list)
   {
       rule = list_entry(p, struct pdsfw_rule, list);

       //check the protocol
       if ((rule->protocol == 't') && (ip_header->protocol != 6))
       {
           //printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", rule->id);
           continue;
       }
       else if ((rule->protocol == 'u') && (ip_header->protocol != 17))
       {
           //printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", rule->id);
           continue;
       }
       else if ((rule->protocol == 'm') && (ip_header->protocol != 1)) 
       {
            //printk(KERN_INFO "rule %d not match: rule-ICMP, packet->not ICMP\n", rule->id);
            continue;
       }

        //check the ip address
        if(rule->src_ip == 0)
        {
            //any
        }
        else
        {
            if (!CheckIP(src_ip, rule->src_ip))
            {
                //printk(KERN_INFO "rule %d not match: src ip mismatch\n", rule->id);
                continue;
            }
        }
 
        if (rule->dst_ip == 0)
        {
            //any
        }
        else
        {
            if (!CheckIP(dest_ip, rule->dst_ip))
            {
                //printk(KERN_INFO "rule %d not match: dest ip mismatch\n", rule->id);                  
                continue;
            }
        }

        //check the port number
        if(rule->src_port == 0)
        {
            //not specified
        }
        else if (src_port != rule->src_port)
        {
           //printk(KERN_INFO "rule %d not match: src port mismatch\n", rule->id);
           continue;
        }

        if(rule->dst_port == 0)
        {
            //not specified
        }
        else if(dest_port != rule->dst_port)
        {
           //printk(KERN_INFO "rule %d not match: dest port mismatch\n", rule->id);
           continue;
        }

       //a match is found: take action
       if (rule->action == 'd')
       {
           printk(KERN_INFO "a match is found: %d, drop the packet\n", rule->id);
           return NF_DROP;
       }
       else
       {
           printk(KERN_INFO "a match is found: %d, accept the packet\n", rule->id);
           return NF_ACCEPT;
       }
   }
 
   printk(KERN_INFO "No match is found, accepting the packet\n");

   return NF_ACCEPT;                
}


//
//  Initialization of module
//
int init_module(void)
{
    //Create proc file to communicate with user space
    //if(!(proc = proc_create(FILE_NAME, 0644, NULL, &procFops)))  --- requires super user privilegies to write to proc file
    if(!(proc = proc_create(FILE_NAME, 0666, NULL, &fops)))
    {
        printk(KERN_INFO "Initializing pdsfw kernel module: FAILED\n");
        return -ENOMEM;
    }

    //allocate memory for buffer
    procf_buffer = (char*)vmalloc(MAX_SIZE);

    //Create list for firewall rules
    INIT_LIST_HEAD(&(pdsfw_rule_list.list));

    //Register netfilter hooks // only incoming packets are filtered []
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
 
    nf_register_hook(&nfho);

    printk(KERN_INFO "Initializing pdsfw kernel module: SUCCESS\n");

    return 0;
}

//
//  Clean up function, 
//  
void cleanup_module(void)
{
    struct list_head *p, *q;
    struct pdsfw_rule *rule;

    nf_unregister_hook(&nfho);
    
    printk(KERN_INFO "Free policy list\n");
    
    list_for_each_safe(p, q, &pdsfw_rule_list.list)
    {
        rule = list_entry(p, struct pdsfw_rule, list);
        printk(KERN_INFO "Free rule: ID =%d: SUCCESS\n",rule->id);
        list_del(p);
        kfree(rule);
    }

    printk(KERN_INFO "Removing pdsfw kernel module\n");
    remove_proc_entry(FILE_NAME, NULL);
}
//TODO AVL strom maybe
//TODO SEQ file