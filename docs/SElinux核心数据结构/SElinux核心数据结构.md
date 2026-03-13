# SELinux 核心数据结构

## 1. 基础数据结构

### 1.1 扩展位图 (Extended Bitmap)
#### struct ebitmap_node
#### struct ebitmap

### 1.2 哈希表 (Hash Table)
#### struct hashtab_key_params
#### struct hashtab_node
#### struct hashtab_info
#### struct hashtab

### 1.3 访问向量表 (AVT)
#### struct avtab_key
#### struct avtab_extended_perms
#### struct avtab_datum
#### struct avtab_node
#### struct avtab

### 1.4 条件策略 (Conditional Policy)
#### struct cond_expr_node
#### struct cond_expr
#### struct cond_av_list
#### struct cond_node

### 1.5 约束与 MLS (Constraints & MLS)
#### struct constraint_expr
#### struct constraint_node
#### struct mls_level
#### struct mls_range

## 2. 策略数据库核心 (Policy Database)

### 2.1 策略元素定义
#### struct perm_datum
#### struct common_datum
#### struct class_datum
#### struct role_datum
#### struct role_trans_key
#### struct role_trans_datum
#### struct filename_trans_key
#### struct filename_trans_datum
#### struct role_allow
#### struct type_datum
#### struct user_datum
#### struct level_datum
#### struct cat_datum
#### struct range_trans
#### struct cond_bool_datum
#### struct type_set
#### struct ocontext
#### struct genfs

### 2.2 策略总控

#### struct policy_file

#### struct policy_data

#### struct policydb


```c
// O:\security\selinux\ss\services.h
/* Mapping for a single class */
struct selinux_mapping {
	u16 value; /* policy value for class */
	u16 num_perms; /* number of permissions in class */
	u32 perms[sizeof(u32) * 8]; /* policy values for permissions */
};

/* Map for all of the classes, with array size */
struct selinux_map {
	struct selinux_mapping *mapping; /* indexed by class */
	u16 size; /* array size of mapping */
};

struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	struct selinux_map map;
	u32 latest_granting;
} __randomize_layout;
```

* 最核心的策略数据库结构。它是在内核启动时或用户态加载策略文件（binary policy）后，解析生成的内存驻留策略表示。所有的权限检查最终都依赖于这个结构中的数据







#### struct policydb_compat_info

### 2.3 SID 映射表
#### struct sidtab_entry
#### struct sidtab_node_leaf
#### struct sidtab_node_inner
#### struct sidtab_isid_entry
#### struct sidtab_convert_params
#### struct sidtab
#### struct sidtab_str_cache

### 2.4 内部服务封装
#### struct selinux_mapping
#### struct selinux_map
#### struct selinux_policy
#### struct convert_context_args
#### struct selinux_policy_convert_data
#### struct selinux_audit_rule

## 3. 运行时缓存 (Access Vector Cache)

### 3.1 缓存条目与节点
#### struct avc_entry
#### struct avc_node
#### struct avc_xperms_decision_node
#### struct avc_xperms_node

### 3.2 缓存管理
#### struct avc_cache_stats
#### struct avc_cache
#### struct avc_callback_node
#### struct selinux_avc

### 3.3 决策辅助结构
#### struct av_decision
#### struct extended_perms_data
#### struct extended_perms_decision
#### struct extended_perms
#### struct selinux_audit_data

## 4. 全局状态与加载机制

### 4.1 全局状态
#### struct selinux_kernel_status
#### struct selinux_load_state
#### struct selinux_state


```c
// O:\security\selinux\include\security.h
struct selinux_policy;

struct selinux_state {
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	bool enforcing; // 决定 SELinux 是处于强制模式 (Enforcing) 还是 宽容模式 (Permissive)
#endif
	bool initialized; // 标记 SELinux 子系统是否已完成初始化（即策略是否已加载）防止还未初始化就进行安全检查
	bool policycap[__POLICYDB_CAP_MAX]; // 策略能力位图（Policy Capabilities）

	struct page *status_page; // 状态页与锁机制，基于页的同步机制
	struct mutex status_lock;

	struct selinux_policy __rcu *policy; // 指向当前SELinux 策略对象。包含策略数据库、符号表、访问向量缓存的引用等核心数据。
	struct mutex policy_mutex; // 互斥锁，保护策略的加载和替换过程
} __randomize_layout; //对抗内存破坏漏洞。每次内核编译，成员的顺序都可能不同，增加利用难度.
```

* 历史背景：在早期的 Linux 内核中，SELinux 的状态信息（如是否启用、强制模式开关、当前策略指针等）分散在多个独立的全局变量中（例如 selinux_enabled, selinux_enforcing, policydb, sidtab 等）。这种“散弹式”的全局变量管理方式存在耦合度高、难以维护、不利于扩展等问题
* 存储 SELinux 的全局运行时状态。在 6.6 内核中，它取代了早期版本中大量分散的全局变量，实现了更好的封装和多命名空间支持的基础（尽管多命名空间仍在开发中，但结构已准备好）
* 设计目标：
  - 封装性（Encapsulation）：将所有与 SELinux 运行时状态相关的数据聚合到一个结构中，通过操作这个结构体实例来管理状态，而非直接操作散乱的全局变量。
  - 多命名空间支持（Multi-namespace Support）：这是最关键的长远目标。虽然目前（截至 6.6/6.7）Linux 主要支持单例 SELinux 策略，但将状态结构化是为未来实现每个网络命名空间或用户命名空间拥有独立 SELinux 策略打下基础。如果未来需要支持多租户隔离的安全策略，只需为每个命名空间实例化一个 selinux_state 即可，而无需重构整个子系统。
  - 并发安全与随机化布局：配合 __randomize_layout 和 RCU 机制，提高内核抗攻击能力和读写性能。

* struct selinux_state 不仅仅是一个结构体，它是 SELinux 子系统架构演进的里程碑。

| 特性 | 传统实现 (Pre-Refactor) | 现代实现 (struct selinux_state) |
| :--- | :--- | :--- |
| 状态管理 | 分散的全局变量 (`selinux_enforcing`, `policydb` 等) | 集中封装在单一结构体中 |
| 并发模型 | 粗粒度锁或复杂的原子操作 | RCU (读) + Mutex (写) 的清晰分离 |
| 用户态通知 | 轮询或简单的等待队列 | 高效的 mmap status page 机制 |
| 扩展性 | 难以支持多策略实例 | 原生支持多实例（为命名空间做准备） |
| 安全性 | 固定内存布局 | 随机化布局 (`__randomize_layout`) 防利用 |


### 4.2 文件系统与加载
#### struct policy_load_memory
#### struct selinux_fs_info
#### struct selinux_mnt_opts
#### struct lsm_blob_sizes

## 5. 内核对象安全标签 (LSM Blobs)

### 5.1 进程与凭证
#### struct task_security_struct
#### struct cred_security_struct

### 5.2 文件系统对象
#### struct inode_security_struct
#### struct file_security_struct
#### struct superblock_security_struct

### 5.3 IPC 与消息
#### struct ipc_security_struct
#### struct msg_security_struct

### 5.4 网络与 Socket
#### struct sk_security_struct
#### struct tun_security_struct
#### struct netif_security_struct
#### struct netnode_security_struct
#### struct netport_security_struct

### 5.5 其他子系统对象
#### struct key_security_struct
#### struct bpf_security_struct
#### struct perf_event_security_struct
#### struct ib_security_struct
#### struct pkey_security_struct

## 6. 网络与特定子系统缓存

### 6.1 网络缓存
#### struct sel_netif
#### struct sel_netnode_bkt
#### struct sel_netnode
#### struct sel_netport_bkt
#### struct sel_netport

### 6.2 InfiniBand 缓存
#### struct sel_ib_pkey_bkt
#### struct sel_ib_pkey

## 7. 辅助映射与工具

### 7.1 映射表
#### struct nlmsg_perm
#### struct security_class_mapping

### 7.2 临时数据
#### struct cond_insertf_data


























---