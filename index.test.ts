import { pridDerive, pridFromShared, contextSharedSecret, CTX_CONNECTION } from "./index";
import sodium from "libsodium-wrappers";

describe("Spec", () => {
    const SPEC_TEST_VECTOR = {
        input: {
            aliceSecretKey: "0xc9432ed5c0c5c24e8a4ff190619893918b4d1265a67d123895023fa7324b43e0",
            alicePublicKey: "0x0fea2cafabdc83752be36fa5349640da2c828add0a290df13cd2d8173eb2496f",
            bobSecretKey: "0xdc106e1371293ee9536956e1253f43f8941d4a5c4e40f15968d24b75512b6920",
            bobPublicKey: "0xd0d4eb21db1df63369c147e63b2573816dd4b3fe513e95bf87f7ed1835407e62",
            aliceId: 42n,
            bobId: 478n,
            context: "PRIdCtx0",
        },
        output: {
            aliceToBobPrid: "0xace4d2995b1a829c",
            aliceToBobSharedCtx: "0x37cb1a870f0c1dce06f5116faf145ac2cf7a2f7d30136be4eea70c324932e6d2",
            bobToAlicePrid: "0x1a53b02a26503600",
            bobToAliceSharedCtx: "0x32c45c49fcfe12f9db60e74fa66416c5a05832c298814d82032a6783a4b1fca0",
        }
    }

    beforeAll(async () => {
        await sodium.ready;
    });

    describe("PRId Derivation", () => {
        it("Alice to Bob Match", async () => {
            const { input: { aliceSecretKey, alicePublicKey, bobSecretKey, bobPublicKey, aliceId, bobId, context } } = SPEC_TEST_VECTOR;
            const aliceVersion = await pridDerive(aliceSecretKey, bobPublicKey, aliceId, bobId, context);
            const bobVersion = await pridDerive(bobSecretKey, alicePublicKey, aliceId, bobId, context);
            expect(aliceVersion).toEqual(SPEC_TEST_VECTOR.output.aliceToBobPrid);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Bob to Alice Match", async () => {
            const { input: { aliceSecretKey, alicePublicKey, bobSecretKey, bobPublicKey, aliceId, bobId, context } } = SPEC_TEST_VECTOR;
            const aliceVersion = await pridDerive(aliceSecretKey, bobPublicKey, bobId, aliceId, context);
            const bobVersion = await pridDerive(bobSecretKey, alicePublicKey, bobId, aliceId, context);
            expect(aliceVersion).toEqual(SPEC_TEST_VECTOR.output.bobToAlicePrid);
            expect(aliceVersion).toEqual(bobVersion);
        });
    });

    describe("Context Shared Secret", () => {
        it("Alice to Bob Matches", async () => {
            const { input: { aliceSecretKey, alicePublicKey, bobSecretKey, bobPublicKey, bobId, context } } = SPEC_TEST_VECTOR;
            const aliceVersion = await contextSharedSecret(sodium.from_hex(aliceSecretKey.replace("0x", "")), sodium.from_hex(bobPublicKey.replace("0x", "")), bobId, context);
            const bobVersion = await contextSharedSecret(sodium.from_hex(bobSecretKey.replace("0x", "")), sodium.from_hex(alicePublicKey.replace("0x", "")), bobId, context);
            expect("0x" + sodium.to_hex(aliceVersion)).toEqual(SPEC_TEST_VECTOR.output.aliceToBobSharedCtx);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Bob to Alice Matches", async () => {
            const { input: { aliceSecretKey, alicePublicKey, bobSecretKey, bobPublicKey, aliceId, context } } = SPEC_TEST_VECTOR;
            const aliceVersion = await contextSharedSecret(sodium.from_hex(aliceSecretKey.replace("0x", "")), sodium.from_hex(bobPublicKey.replace("0x", "")), aliceId, context);
            const bobVersion = await contextSharedSecret(sodium.from_hex(bobSecretKey.replace("0x", "")), sodium.from_hex(alicePublicKey.replace("0x", "")), aliceId, context);
            expect("0x" + sodium.to_hex(aliceVersion)).toEqual(SPEC_TEST_VECTOR.output.bobToAliceSharedCtx);
            expect(aliceVersion).toEqual(bobVersion);
        });
    })
});

describe("Random", () => {
    let aliceSecretKey: Uint8Array;
    let alicePublicKey: Uint8Array;
    let bobSecretKey: Uint8Array;
    let bobPublicKey: Uint8Array;
    let aliceId: bigint;
    let bobId: bigint;

    beforeEach(async () => {
        await sodium.ready;
        ({ privateKey: aliceSecretKey, publicKey: alicePublicKey } = sodium.crypto_box_keypair());
        ({ privateKey: bobSecretKey, publicKey: bobPublicKey } = sodium.crypto_box_keypair());
        aliceId = BigInt(Math.floor(Math.random() * 1_000));
        bobId = BigInt(Math.floor(Math.random() * 1_000));
    });

    describe("PRId Derivation", () => {
        it("Alice to Bob Match", async () => {
            const aliceVersion = await pridDerive(aliceSecretKey, bobPublicKey, aliceId, bobId, CTX_CONNECTION);
            const bobVersion = await pridDerive(bobSecretKey, alicePublicKey, aliceId, bobId, CTX_CONNECTION);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Bob to Alice Match", async () => {
            const aliceVersion = await pridDerive(aliceSecretKey, bobPublicKey, bobId, aliceId, CTX_CONNECTION);
            const bobVersion = await pridDerive(bobSecretKey, alicePublicKey, bobId, aliceId, CTX_CONNECTION);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Alice to Bob does not match Bob to Alice", async () => {
            const aliceVersionAliceToBob = await pridDerive(aliceSecretKey, bobPublicKey, bobId, aliceId, CTX_CONNECTION);
            const aliceVersionBobToAlice = await pridDerive(aliceSecretKey, bobPublicKey, aliceId, bobId, CTX_CONNECTION);
            expect(aliceVersionAliceToBob).not.toEqual(aliceVersionBobToAlice);
        });
    });

    describe("Context Shared Secret", () => {
        it("Alice to Bob Matches", async () => {
            const aliceVersion = await contextSharedSecret(aliceSecretKey, bobPublicKey, bobId, CTX_CONNECTION);
            const bobVersion = await contextSharedSecret(bobSecretKey, alicePublicKey, bobId, CTX_CONNECTION);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Bob to Alice Matches", async () => {
            const aliceVersion = await contextSharedSecret(aliceSecretKey, bobPublicKey, aliceId, CTX_CONNECTION);
            const bobVersion = await contextSharedSecret(bobSecretKey, alicePublicKey, aliceId, CTX_CONNECTION);
            expect(aliceVersion).toEqual(bobVersion);
        });

        it("Alice to Bob does NOT match Bob to Alice", async () => {
            const aliceVersionAlice = await contextSharedSecret(aliceSecretKey, bobPublicKey, aliceId, CTX_CONNECTION);
            const aliceVersionBob = await contextSharedSecret(aliceSecretKey, bobPublicKey, bobId, CTX_CONNECTION);
            expect(aliceVersionAlice).not.toEqual(aliceVersionBob);
        });
    })
});

