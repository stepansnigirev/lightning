#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/ccan/crypto/sha256/sha256.h>
#include <ccan/ccan/mem/mem.h>
#include <ccan/ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/lease_rates.h>
#include <common/overflows.h>
#include <common/type_to_string.h>
#include <wire/peer_wire.h>

/* FIXME: Is there a better way to do this ? */
bool lease_rates_eq(struct lease_rates *l1,
		    struct lease_rates *l2)
{
	if (!l1 != !l2)
		return false;

	if (!l1)
		return true;

	return l1->funding_weight == l2->funding_weight
		&& l1->channel_fee_max_base_msat == l2->channel_fee_max_base_msat
		&& l1->channel_fee_max_proportional_thousandths == l2->channel_fee_max_proportional_thousandths
		&& l1->lease_fee_base_sat == l2->lease_fee_base_sat
		&& l1->lease_fee_basis == l2->lease_fee_basis;
}

bool lease_rates_empty(struct lease_rates *rates)
{
	if (!rates)
		return true;

	/* FIXME: why can't i do memeqzero? */
	return rates->funding_weight == 0
		&& rates->channel_fee_max_base_msat == 0
		&& rates->channel_fee_max_proportional_thousandths == 0
		&& rates->lease_fee_base_sat == 0
		&& rates->lease_fee_basis == 0;
}

void lease_rates_get_commitment(struct pubkey *pubkey,
				u32 lease_expiry,
				u32 chan_fee_msat,
				u16 chan_fee_ppt,
				struct sha256 *sha)
{
	struct sha256_ctx sctx = SHA256_INIT;
	u8 der[PUBKEY_CMPR_LEN];
	/* BOLT- #2:
	 * - MUST set `signature` to the ECDSA signature of
	 *   SHA256("option_will_fund"
	 *          || `funding_pubkey`
	 *   	    || `blockheight` + 4032
	 *   	    || `channel_fee_max_base_msat`
	 *   	    || `channel_fee_max_proportional_thousandths`)
	 *   using the node_id key.
	 */
	pubkey_to_der(der, pubkey);
	sha256_update(&sctx, "option_will_fund", strlen("option_will_fund"));
	sha256_update(&sctx, der, PUBKEY_CMPR_LEN);
	sha256_be32(&sctx, lease_expiry);
	sha256_be32(&sctx, chan_fee_msat);
	sha256_be16(&sctx, chan_fee_ppt);
	sha256_done(&sctx, sha);
}

bool lease_rates_calc_fee(struct lease_rates *rates,
			  struct amount_sat accept_funding_sats,
			  struct amount_sat requested_sats,
			  u32 onchain_feerate,
			  struct amount_sat *fee)
{
	struct amount_sat lease_fee, basis_sat, tx_fee;
	/* BOLT- #2:
	 * The lease fee is calculated as:
	 * `lease_fee_base_sat` +
	 * min(`accept_channel2`.`funding_satoshis`, `open_channel2`.`requested_sats`) * `lease_fee_basis` / 10_000 +
	 * `funding_weight` * `funding_feerate_perkw` / 1000
	 */

	lease_fee = amount_sat(rates->lease_fee_base_sat);
	basis_sat = amount_sat_less(accept_funding_sats, requested_sats)
		? accept_funding_sats : requested_sats;

	if (!amount_sat_scale(&basis_sat, basis_sat,
			      rates->lease_fee_basis))
		return false;

	basis_sat = amount_sat_div(basis_sat, 10000);

	if (!amount_sat_add(&lease_fee, lease_fee, basis_sat))
		return false;

	tx_fee = amount_tx_fee(onchain_feerate, rates->funding_weight);
	if (!amount_sat_add(&lease_fee, lease_fee, tx_fee))
		return false;

	*fee = lease_fee;
	return true;
}

bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates,
					struct amount_msat amt)
{
	return assign_overflow_u32(&rates->channel_fee_max_base_msat,
				   amt.millisatoshis); /* Raw: conversion */
}

bool lease_rates_set_lease_fee_sat(struct lease_rates *rates,
				   struct amount_sat amt)
{
	return assign_overflow_u32(&rates->lease_fee_base_sat,
				   amt.satoshis); /* Raw: conversion */
}

char *lease_rates_tohex(const tal_t *ctx, const struct lease_rates *rates)
{
	char *hex;
	u8 *data = tal_arr(NULL, u8, 0);
	towire_lease_rates(&data, rates);
	hex = tal_hex(ctx, data);
	tal_free(data);
	return hex;
}

bool lease_rates_fromhex(const tal_t *ctx,
			 const char *hexdata, size_t hexlen,
			 struct lease_rates **rates)
{
	const u8 *data = tal_hexdata(ctx, hexdata, hexlen);
	size_t len = tal_bytelen(data);

	*rates = tal(ctx, struct lease_rates);
	fromwire_lease_rates(&data, &len, *rates);

	if (data == NULL) {
		tal_free(*rates);
		return false;
	}

	return true;
}

char *lease_rates_fmt(const tal_t *ctx, const struct lease_rates *rates)
{
	return tal_fmt(ctx, "{channel_fee_max_base_msat=%u,"
		       "channel_fee_max_ppt=%u,"
		       "funding_weight=%u,"
		       "lease_fee_base_sat=%u,"
		       "lease_fee_basis=%u}",
		       rates->channel_fee_max_base_msat,
		       rates->channel_fee_max_proportional_thousandths,
		       rates->funding_weight,
		       rates->lease_fee_base_sat,
		       rates->lease_fee_basis);
}