# Keccak256

Use this to compute Keccak256 (Ethereum style) hashes.  For example, it can compute transaction hashes or function selectors.

Published on Nuget with package name: `Keccak256`

## Example:

```
using Epoche;

var hash = Keccak256.ComputeHash("transfer(address,uint256)"); 
// yields a byte array: a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
```

Or to compute an ethereum function selector:

```
string hash = Keccak256.ComputeEthereumFunctionSelector("transfer(address,uint256)");
// 0xa9059cbb
```