import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

Clarinet.test({
  name: "Ensures core data management features work",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const user1 = accounts.get('wallet_1')!;
    const user2 = accounts.get('wallet_2')!;

    // Test data storage
    let block = chain.mineBlock([
      Tx.contractCall('core_guard', 'store-data', [
        types.utf8("encrypted-test-data")
      ], user1.address)
    ]);
    block.receipts[0].result.expectOk().expectBool(true);

    // Test access control with expiration
    const futureTime = 1000000;
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'grant-access', [
        types.principal(user2.address),
        types.some(types.uint(futureTime))
      ], user1.address)
    ]);
    block.receipts[0].result.expectOk().expectBool(true);

    // Test data access
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'access-data', [
        types.principal(user1.address)
      ], user2.address)
    ]);
    block.receipts[0].result.expectOk().expectUtf8("encrypted-test-data");
  }
});

Clarinet.test({
  name: "Tests batch permission management",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const user1 = accounts.get('wallet_1')!;
    const user2 = accounts.get('wallet_2')!;
    const user3 = accounts.get('wallet_3')!;
    const user4 = accounts.get('wallet_4')!;

    // Test batch access grant
    let block = chain.mineBlock([
      Tx.contractCall('core_guard', 'store-data', [
        types.utf8("batch-test-data")
      ], user1.address),
      Tx.contractCall('core_guard', 'grant-batch-access', [
        types.list([
          types.principal(user2.address),
          types.principal(user3.address),
          types.principal(user4.address)
        ]),
        types.none()
      ], user1.address)
    ]);
    
    block.receipts[1].result.expectOk().expectUint(1);

    // Test access for batch users
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'access-data', [
        types.principal(user1.address)
      ], user2.address),
      Tx.contractCall('core_guard', 'access-data', [
        types.principal(user1.address)
      ], user3.address)
    ]);
    
    block.receipts[0].result.expectOk().expectUtf8("batch-test-data");
    block.receipts[1].result.expectOk().expectUtf8("batch-test-data");

    // Test batch revocation
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'revoke-batch-access', [
        types.uint(1)
      ], user1.address)
    ]);
    
    block.receipts[0].result.expectOk().expectBool(true);

    // Verify access revoked
    block = chain.mineBlock([
      Tx.contractCall('core_guard', 'access-data', [
        types.principal(user1.address)
      ], user2.address)
    ]);
    
    block.receipts[0].result.expectErr(types.uint(100));
  }
});
