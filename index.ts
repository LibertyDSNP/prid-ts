import sodium from "libsodium-wrappers";

export type PRId = string;
export type Id = bigint;

export const CTX_CONNECTION = "PRIdCtx0";

export const pridDerive = async (fromSecretKey: Uint8Array | string, toPublicKey: Uint8Array | string, fromId: Id, toId: Id, context: string): Promise<PRId> => {
    await sodium.ready;

    fromSecretKey = typeof fromSecretKey === "string" ? sodium.from_hex(fromSecretKey.replace("0x", "")) : fromSecretKey;
    toPublicKey = typeof toPublicKey === "string" ? sodium.from_hex(toPublicKey.replace("0x", "")) : toPublicKey;

    const ctxSharedSecret = await contextSharedSecret(fromSecretKey, toPublicKey, toId, context);

    return await pridFromShared(ctxSharedSecret, fromId, toId);
}

export const contextSharedSecret = async (fromSecretKey: Uint8Array, toPublicKey: Uint8Array, toId: bigint, ctx: string): Promise<Uint8Array> => {
    await sodium.ready;
    const rootSharedSecret = sodium.crypto_box_beforenm(toPublicKey, fromSecretKey);

    if (toId > Number.MAX_SAFE_INTEGER) {
        throw new Error("Library does not support ids larger than " + Number.MAX_SAFE_INTEGER);
    }

    return sodium.crypto_kdf_derive_from_key(32, Number(toId), ctx, rootSharedSecret);
}

export const pridFromShared = async (ctxSharedSecret: Uint8Array, fromId: Id, toId: Id): Promise<PRId> => {
    const msg = uint64ToLE(toId, 8);
    const nonce = uint64ToLE(fromId, 24);

    await sodium.ready;

    const { cipher } = sodium.crypto_secretbox_detached(msg, nonce, ctxSharedSecret);

    return "0x" + sodium.to_hex(cipher);
}

const uint64ToLE = (x: bigint, bytes: number): Uint8Array => {
    const arr = new Uint8Array(bytes);

    const lo = Number(x & BigInt("0xffffffff"));
    const hi = Number((x >> BigInt(32)) & BigInt("0xffffffff"));

    arr.set([lo & 0xff, (lo >> 8) & 0xff, (lo >> 16) & 0xff, (lo >> 24) & 0xff], 0);
    arr.set([hi & 0xff, (hi >> 8) & 0xff, (hi >> 16) & 0xff, (hi >> 24) & 0xff], 4);

    return arr;
}
