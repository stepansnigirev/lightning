#include "bitcoin/block.h"
#include "bitcoin/pullpush.h"
#include "bitcoin/tx.h"
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>

static bool is_dynafed(le32 version){
	return (version>>31) == 1;
}

static struct elements_dynafed_params *
pull_elements_dynafed_params(const tal_t *ctx, const u8 **cursor, size_t *max){
	struct elements_dynafed_params *params = tal(ctx, struct elements_dynafed_params);
	size_t dynafed_type = pull_varint(cursor, max);
	params->dynafed_type = dynafed_type;
	size_t blob_len;
	if(dynafed_type > 0)
	{
		blob_len = pull_varint(cursor, max);
		params->signblockscript = tal_arr(params, u8, blob_len);
		pull(cursor, max, params->signblockscript, blob_len);
		params->signblock_witness_limit = pull_le32(cursor, max);
	}

	if(dynafed_type == 1){
		params->elided_root = tal_arr(params, u8, 32);
		pull(cursor, max, params->elided_root, 32);
	}else if(dynafed_type == 2){
		blob_len = pull_varint(cursor, max);
		params->fedpeg_program = tal_arr(params, u8, blob_len);
		pull(cursor, max, params->fedpeg_program, blob_len);

		blob_len = pull_varint(cursor, max);
		params->fedpegscript = tal_arr(params, u8, blob_len);
		pull(cursor, max, params->fedpegscript, blob_len);

		size_t ext_space_len = pull_varint(cursor, max);
		params->extension_space = tal_arr(params, u8*, ext_space_len);
		for (size_t i = 0; i < ext_space_len; i++)
		{
			blob_len = pull_varint(cursor, max);
			params->extension_space[i] = tal_arr(params->extension_space, u8, blob_len);
			pull(cursor, max, params->extension_space[i], blob_len);
		}
	}
	return params;
}

static void sha256_dynafed_params(struct sha256_ctx *shactx, struct elements_dynafed_params *params){
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;
	vtlen = varint_put(vt, params->dynafed_type);
	sha256_update(shactx, vt, vtlen);
	size_t len;
	if(params->dynafed_type > 0)
	{
		len = tal_bytelen(params->signblockscript);
		vtlen = varint_put(vt, len);
		sha256_update(shactx, vt, vtlen);
		sha256_update(shactx, params->signblockscript, len);
		sha256_le32(shactx, params->signblock_witness_limit);
	}

	if(params->dynafed_type == 1){
		sha256_update(shactx, params->elided_root, 32);
	}else if(params->dynafed_type == 2){
		len = tal_bytelen(params->fedpeg_program);
		vtlen = varint_put(vt, len);
		sha256_update(shactx, vt, vtlen);
		sha256_update(shactx, params->fedpeg_program, len);

		len = tal_bytelen(params->fedpegscript);
		vtlen = varint_put(vt, len);
		sha256_update(shactx, vt, vtlen);
		sha256_update(shactx, params->fedpegscript, len);

		size_t ext_space_len = tal_count(params->extension_space);
		vtlen = varint_put(vt, ext_space_len);
		sha256_update(shactx, vt, vtlen);
		for (size_t i = 0; i < ext_space_len; i++)
		{
			len = tal_bytelen(params->extension_space[i]);
			vtlen = varint_put(vt, len);
			sha256_update(shactx, vt, vtlen);
			sha256_update(shactx, params->extension_space[i], len);
		}
	}
}

/* Encoding is <blockhdr> <varint-num-txs> <tx>... */
struct bitcoin_block *
bitcoin_block_from_hex(const tal_t *ctx, const struct chainparams *chainparams,
		       const char *hex, size_t hexlen)
{
	struct bitcoin_block *b;
	u8 *linear_tx;
	const u8 *p;
	size_t len, i, num;

	if (hexlen && hex[hexlen-1] == '\n')
		hexlen--;

	/* Set up the block for success. */
	b = tal(ctx, struct bitcoin_block);

	/* De-hex the array. */
	len = hex_data_size(hexlen);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, hexlen, linear_tx, len))
		return tal_free(b);

	b->hdr.version = pull_le32(&p, &len);
	pull(&p, &len, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));
	pull(&p, &len, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));
	b->hdr.timestamp = pull_le32(&p, &len);

	if (is_elements(chainparams)) {
		b->elements_hdr = tal(b, struct elements_block_hdr);
		b->elements_hdr->block_height = pull_le32(&p, &len);

		if(is_dynafed(b->hdr.version)){
			b->elements_hdr->proof.current = pull_elements_dynafed_params(b->elements_hdr, &p, &len);
			b->elements_hdr->proof.proposed = pull_elements_dynafed_params(b->elements_hdr, &p, &len);
			size_t witness_len = pull_varint(&p, &len);
			size_t blob_len;
			b->elements_hdr->proof.witness = tal_arr(b->elements_hdr, u8*, witness_len);
			for (size_t i = 0; i < witness_len; i++)
			{
				blob_len = pull_varint(&p, &len);
				b->elements_hdr->proof.witness[i] = tal_arr(b->elements_hdr->proof.witness, u8, blob_len);
				pull(&p, &len, b->elements_hdr->proof.witness[i], blob_len);
			}
		}else{
			size_t challenge_len = pull_varint(&p, &len);
			b->elements_hdr->proof.challenge = tal_arr(b->elements_hdr, u8, challenge_len);
			pull(&p, &len, b->elements_hdr->proof.challenge, challenge_len);

			size_t solution_len = pull_varint(&p, &len);
			b->elements_hdr->proof.solution = tal_arr(b->elements_hdr, u8, solution_len);
			pull(&p, &len, b->elements_hdr->proof.solution, solution_len);
		}

	} else {
		b->hdr.target = pull_le32(&p, &len);
		b->hdr.nonce = pull_le32(&p, &len);
	}

	num = pull_varint(&p, &len);
	b->tx = tal_arr(b, struct bitcoin_tx *, num);
	for (i = 0; i < num; i++) {
		b->tx[i] = pull_bitcoin_tx(b->tx, &p, &len);
		b->tx[i]->chainparams = chainparams;
	}

	/* We should end up not overrunning, nor have extra */
	if (!p || len)
		return tal_free(b);

	tal_free(linear_tx);
	return b;
}

void bitcoin_block_blkid(const struct bitcoin_block *b,
			 struct bitcoin_blkid *out)
{
	struct sha256_ctx shactx;
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;

	sha256_init(&shactx);
	sha256_le32(&shactx, b->hdr.version);
	sha256_update(&shactx, &b->hdr.prev_hash, sizeof(b->hdr.prev_hash));
	sha256_update(&shactx, &b->hdr.merkle_hash, sizeof(b->hdr.merkle_hash));
	sha256_le32(&shactx, b->hdr.timestamp);

	if (is_elements(chainparams)) {
		sha256_le32(&shactx, b->elements_hdr->block_height);
		if (is_dynafed(b->hdr.version)){
			sha256_dynafed_params(&shactx, b->elements_hdr->proof.current);
			sha256_dynafed_params(&shactx, b->elements_hdr->proof.proposed);
		}else{
			size_t clen = tal_bytelen(b->elements_hdr->proof.challenge);
			vtlen = varint_put(vt, clen);
			sha256_update(&shactx, vt, vtlen);
			sha256_update(&shactx, b->elements_hdr->proof.challenge, clen);
			/* The solution is skipped, since that'd create a circular
			* dependency apparently */
		}
	} else {
		sha256_le32(&shactx, b->hdr.target);
		sha256_le32(&shactx, b->hdr.nonce);
	}
	sha256_double_done(&shactx, &out->shad);
}

/* We do the same hex-reversing crud as txids. */
bool bitcoin_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct bitcoin_blkid *blockid)
{
	struct bitcoin_txid fake_txid;
	if (!bitcoin_txid_from_hex(hexstr, hexstr_len, &fake_txid))
		return false;
	blockid->shad = fake_txid.shad;
	return true;
}

bool bitcoin_blkid_to_hex(const struct bitcoin_blkid *blockid,
			  char *hexstr, size_t hexstr_len)
{
	struct bitcoin_txid fake_txid;
	fake_txid.shad = blockid->shad;
	return bitcoin_txid_to_hex(&fake_txid, hexstr, hexstr_len);
}

static char *fmt_bitcoin_blkid(const tal_t *ctx,
			       const struct bitcoin_blkid *blkid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*blkid)));

	bitcoin_blkid_to_hex(blkid, hexstr, hex_str_size(sizeof(*blkid)));
	return hexstr;
}
REGISTER_TYPE_TO_STRING(bitcoin_blkid, fmt_bitcoin_blkid);
