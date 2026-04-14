# RBAC Permission Scanner

扫描任意 EVM 合约的 RBAC 权限分布，自动识别访问控制模式、发现所有角色及其成员地址，生成结构化 Markdown 报告。

## 支持的访问控制模式

| 模式                           | 说明                                   |
| ------------------------------ | -------------------------------------- |
| **OpenZeppelin AccessManager** | uint64 角色 ID，函数级权限映射         |
| **OpenZeppelin AccessControl** | bytes32 角色哈希，支持 Enumerable 变体 |
| **Ownable / Ownable2Step**     | 单一 owner 管理                        |
| **ERC1967 Proxy**              | 代理管理员及实现合约检测               |

一个合约可以同时匹配多种模式，脚本会全部扫描并汇总到一份报告中。

## 前提条件

- [Foundry](https://book.getfoundry.sh/getting-started/installation)（需要 `cast` 命令）
- [jq](https://jqlang.github.io/jq/download/)

## 快速开始

```bash
bash scripts/scan-permissions.sh <CONTRACT_ADDRESS> <RPC_URL> [FROM_BLOCK]
```

**参数说明：**

| 参数               | 必填 | 说明                                                                    |
| ------------------ | ---- | ----------------------------------------------------------------------- |
| `CONTRACT_ADDRESS` | 是   | 要分析的合约地址                                                        |
| `RPC_URL`          | 是   | 链的 RPC 端点                                                           |
| `FROM_BLOCK`       | 否   | 起始区块号（默认 `0`，RPC 报 block range too large 时传入合约部署区块） |

**示例：**

```bash
# 扫描 Ethereum 主网上的合约
bash scripts/scan-permissions.sh 0x1234...abcd https://eth.llamarpc.com

# 指定起始区块以避免 RPC 查询范围限制
bash scripts/scan-permissions.sh 0x1234...abcd https://eth.llamarpc.com 18000000
```

报告自动保存到当前目录：`rbac-report-<addr_prefix>.md`

## 工作流程

```
输入合约地址
    │
    ▼
┌─────────────────────┐
│  1. 类型检测         │  依次尝试 authority() / ADMIN_ROLE() / DEFAULT_ADMIN_ROLE() / owner() / ERC1967 slot
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  2. 事件扫描         │  抓取 RoleGranted / RoleRevoked / RoleLabel / TargetFunctionRoleUpdated 等事件
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  3. 状态验证         │  对每个候选成员调用 hasRole() 确认当前链上状态
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  4. 生成报告         │  输出 Markdown 格式的权限报告
└─────────────────────┘
```

## 输出报告内容

- **合约元信息**：地址、链 ID、区块高度、扫描时间
- **Ownership**：Owner / Pending Owner / Proxy Admin / Implementation 地址
- **AccessManager Roles**：角色 ID、名称、管理员角色、Guardian、授权延迟、成员列表
- **Function Permissions**：目标合约、函数选择器、函数名、所需角色
- **AccessControl Roles**：角色哈希、已知角色名匹配、管理员角色、成员列表

## 作为 Copilot Skill 使用

本项目同时也是一个 [GitHub Copilot Skill](SKILL.md)。安装后，当你在对话中提到以下关键词时会自动触发：

> 分析合约权限、扫描 RBAC、查看角色分布、权限审计、access control 分析、permission scan、role discovery

或者直接给出合约地址 + RPC URL 并询问权限相关问题即可。

## License

MIT
