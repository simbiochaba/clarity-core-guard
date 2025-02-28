import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

[... existing tests unchanged ...]

Clarinet.test({
  name: "Ensures data deletion works correctly",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const user1 = accounts.get('wallet_1')!;
    
    // Store data
    let block = chain.mineBlock([
      Tx.contractCall('core_guard', 'store-data', [
        types.utf8("test-data")
      ], user1.address)
    ]);
    block.receipts[0].result.expectOk().expectBool(true);
    
    // Delete data
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'delete-data', [], user1.address)
    ]);
    block.receipts[0].result.expectOk().expectBool(true);
    
    // Verify deletion
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'access-data', [
        types.principal(user1.address)
      ], user1.address)
    ]);
    block.receipts[0].result.expectErr(types.uint(102)); // err-no-data
  }
});

[... additional tests for expiration and batch validation ...]
