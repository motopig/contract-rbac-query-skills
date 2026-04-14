---
name: "rbac-scanner"
description: "扫描 EVM 合约的 RBAC 权限分布，发现所有角色及其成员地址。支持 OpenZeppelin AccessManager (uint64 roles)、AccessControl (bytes32 roles)、Ownable 和 ERC1967 代理模式。输入合约地址和 RPC URL，输出 Markdown 权限报告。当用户提到分析合约权限、扫描 RBAC、查看角色分布、权限审计、access control 分析、permission scan、role discovery 时触发。也在用户给出合约地址 + RPC 并想了解谁有什么权限时触发。"
version: "1.0"
keywords: ["rbac", "permissions", "access control", "roles", "access manager", "ownable", "evm", "foundry", "cast"]
---

# RBAC Permission Scanner

扫描任意 EVM 合约的权限分布，自动发现所有角色和对应的权限地址，生成 Markdown 报告。

## 前提条件

- **Foundry** (`cast` 命令可用)
- **jq** (JSON 解析)

## 使用方式

运行 helper 脚本（相对于本 SKILL.md 所在目录）：

```bash
bash <SKILL_DIR>/scripts/scan-permissions.sh <CONTRACT_ADDRESS> <RPC_URL> [FROM_BLOCK]
```

- `CONTRACT_ADDRESS`: 要分析的合约地址（可以是 AccessManager 本身、被管理的合约、AccessControl 合约、或 Ownable 合约）
- `RPC_URL`: 链的 RPC 端点
- `FROM_BLOCK`: 起始区块号（默认 0；如果 RPC 报错 block range too large，传入合约部署区块号）

报告自动保存到当前工作目录：`rbac-report-<addr_prefix>.md`

## 工作流

### 1. 类型检测

脚本会自动尝试以下检测（按顺序）：

| 调用 | 成功说明 |
|------|---------|
| `authority()(address)` | 合约是 AccessManaged，返回值是 AccessManager 地址 |
| `ADMIN_ROLE()(uint64)` | 合约本身就是 AccessManager |
| `DEFAULT_ADMIN_ROLE()(bytes32)` | 合约使用 AccessControl |
| `owner()(address)` | 合约使用 Ownable |
| 读取 ERC1967 admin slot | 合约是可升级代理 |

一个合约可能同时匹配多种模式。

### 2. AccessManager 扫描

通过以下事件查询角色和权限：

| 事件 | 用途 |
|------|------|
| `RoleGranted(uint64,address,uint32,uint48,bool)` | 发现所有角色授予记录 |
| `RoleRevoked(uint64,address)` | 发现所有角色撤销记录 |
| `RoleLabel(uint64,string)` | 获取角色名称 |
| `TargetFunctionRoleUpdated(address,bytes4,uint64)` | 获取函数→角色映射 |

然后用 `hasRole(uint64,address)` 验证当前状态，用 `getRoleAdmin/getRoleGuardian/getRoleGrantDelay` 获取角色配置。

### 3. AccessControl 扫描

- 优先使用 `getRoleMemberCount` + `getRoleMember`（如果合约是 AccessControlEnumerable）
- 否则通过 `RoleGranted(bytes32,address,address)` 事件发现候选成员，用 `hasRole(bytes32,address)` 验证
- 自动匹配常见角色名：DEFAULT_ADMIN_ROLE, MINTER_ROLE, PAUSER_ROLE, BURNER_ROLE, UPGRADER_ROLE, OPERATOR_ROLE 等

### 4. Ownable / 代理扫描

- `owner()` 获取当前 owner
- `pendingOwner()` 检查 Ownable2Step
- ERC1967 admin slot (`0xb53127684a...`) 获取代理管理员

## 手动回退命令

如果脚本执行失败，可以手动执行以下 cast 命令：

```bash
# 检测类型
cast call <ADDR> "authority()(address)" --rpc-url <RPC>
cast call <ADDR> "owner()(address)" --rpc-url <RPC>

# AccessManager: 获取角色授予事件
cast logs "RoleGranted(uint64,address,uint32,uint48,bool)" \
  --from-block <BLOCK> --address <MANAGER_ADDR> --rpc-url <RPC> --json

# AccessManager: 获取函数权限映射
cast logs "TargetFunctionRoleUpdated(address,bytes4,uint64)" \
  --from-block <BLOCK> --address <MANAGER_ADDR> --rpc-url <RPC> --json

# AccessManager: 验证角色成员
cast call <MANAGER_ADDR> "hasRole(uint64,address)(bool,uint32)" <ROLE_ID> <ACCOUNT> --rpc-url <RPC>

# AccessManager: 获取角色配置
cast call <MANAGER_ADDR> "getRoleAdmin(uint64)(uint64)" <ROLE_ID> --rpc-url <RPC>

# AccessControl: 获取角色授予事件
cast logs "RoleGranted(bytes32,address,address)" \
  --from-block <BLOCK> --address <ADDR> --rpc-url <RPC> --json

# AccessControl: 验证角色
cast call <ADDR> "hasRole(bytes32,address)(bool)" <ROLE_BYTES32> <ACCOUNT> --rpc-url <RPC>

# 函数选择器查找
cast 4byte <SELECTOR>

# 代理 admin slot
cast storage <ADDR> 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url <RPC>
```

## 事件 JSON 解析参考

`cast logs --json` 返回的日志中：
- `topics[0]` = 事件签名哈希
- `topics[1..3]` = indexed 参数（左填充到 32 字节）
- `data` = 非 indexed 参数的 ABI 编码

地址从 topic 提取：取最后 40 个十六进制字符，加 `0x` 前缀。
uint64 从 topic 提取：直接用 `printf "%d"` 转十进制。
bytes4 从 data 提取：取前 8 个十六进制字符（去掉 `0x` 后）。

## 常见问题

- **RPC 报 block range too large**：传入合约部署区块号作为 FROM_BLOCK
- **事件数量为 0**：可能合约刚部署、还没有角色配置，或 FROM_BLOCK 设置过大
- **cast 4byte 查不到函数名**：正常，未注册的自定义函数不会在 4byte directory 中
- **hasRole 返回 false 但事件中有 grant**：角色已被撤销，或 grant delay 尚未到期

## 报告格式

报告保存为 Markdown 文件，包含：
1. 合约基本信息（地址、链 ID、区块高度、检测到的模式）
2. 所有权信息（Owner、Proxy Admin）
3. 角色成员列表（按角色分组，含执行延迟）
4. 函数权限映射（Target → Selector → Function Name → Required Role）
5. 角色层级（Admin Role、Guardian Role、Grant Delay）
