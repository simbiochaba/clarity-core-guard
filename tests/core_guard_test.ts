import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

Clarinet.test({
    name: "Ensures users can store and manage their data",
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

        // Test access control
        block = chain.mineBlock([
            Tx.contractCall('core_guard', 'grant-access', [
                types.principal(user2.address)
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

        // Test access revocation
        block = chain.mineBlock([
            Tx.contractCall('core_guard', 'revoke-access', [
                types.principal(user2.address)
            ], user1.address)
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // Test unauthorized access
        block = chain.mineBlock([
            Tx.contractCall('core_guard', 'access-data', [
                types.principal(user1.address)
            ], user2.address)
        ]);
        block.receipts[0].result.expectErr(types.uint(100));

        // Test access logs
        block = chain.mineBlock([
            Tx.contractCall('core_guard', 'get-access-logs', [
                types.principal(user1.address)
            ], user1.address)
        ]);
        const logs = block.receipts[0].result.expectOk().expectSome();
        assertEquals(logs['access-count'], types.uint(1));
    }
});