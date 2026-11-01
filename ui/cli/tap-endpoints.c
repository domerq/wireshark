/* tap-endpoints.c
 * endpoints   2014 Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/str_util.h>
#include <ui/cli/tshark-tap.h>
#include <ui/cli/conv-merge.h>

typedef struct _endpoints_t {
	const char *type;
	const char *filter;
	unsigned table;			/* this table's place among the -z tables */
	tap_packet_cb packet_func;	/* the dissector's, when rows are counted */
	conv_hash_t hash;
} endpoints_t;

/*
 * A worker of a flow-sharded run has to say which frame created each of
 * its rows: the parent folds the workers' tables together and prints
 * them in the order the capture as a whole created them, which is the
 * order rows of the same size come out in.
 */
static tap_packet_status
endpoints_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt,
	const void *data, tap_flags_t flags)
{
	conv_hash_t *hash = (conv_hash_t *)arg;
	endpoints_t *iu = (endpoints_t *)hash->user_data;
	unsigned before = hash->conv_array ? hash->conv_array->len : 0;
	tap_packet_status status;
	unsigned after;

	status = iu->packet_func(arg, pinfo, edt, data, flags);

	after = hash->conv_array ? hash->conv_array->len : 0;
	conv_merge_rows_added(iu->table, after - before, pinfo->num);

	return status;
}

static void
endpoints_draw(void *arg)
{
	conv_hash_t *hash = (conv_hash_t*)arg;
	endpoints_t *iu = (endpoints_t *)hash->user_data;
	endpoint_item_t *endpoint;
	uint64_t last_frames, max_frames;
	unsigned i;
	bool display_port = (!strncmp(iu->type, "TCP", 3) || !strncmp(iu->type, "UDP", 3) || !strncmp(iu->type, "SCTP", 4)) ? true : false;

	/* A worker hands its rows to the parent rather than printing a
	 * table that would cover only its own flows. */
	if (!conv_merge_draw(iu->table))
		return;

	printf("================================================================================\n");
	printf("%s Endpoints\n", iu->type);
	printf("Filter:%s\n", iu->filter ? iu->filter : "<No Filter>");

	printf("                       | %sPackets | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |\n",
		display_port ? " Port  | | " : "");

	max_frames = UINT_MAX;
	do {
		last_frames = 0;
		for (i=0; (iu->hash.conv_array && i < iu->hash.conv_array->len); i++) {
			uint64_t tot_frames;

			endpoint = &g_array_index(iu->hash.conv_array, endpoint_item_t, i);
			tot_frames = endpoint->rx_frames + endpoint->tx_frames;

			if ((tot_frames > last_frames) && (tot_frames < max_frames)) {
				last_frames = tot_frames;
			}
		}

		for (i=0; (iu->hash.conv_array && i < iu->hash.conv_array->len); i++) {
			uint64_t tot_frames;
			char *conversation_str, *port_str;

			endpoint = &g_array_index(iu->hash.conv_array, endpoint_item_t, i);
			tot_frames = endpoint->rx_frames + endpoint->tx_frames;

			if (tot_frames == last_frames) {
				/* XXX - TODO: make name resolution configurable (through gbl_resolv_flags?) */
				conversation_str = get_conversation_address(NULL, &endpoint->myaddress, true);
				if (display_port) {
					/* XXX - TODO: make port resolution configurable (through gbl_resolv_flags?) */
					port_str = get_endpoint_port(NULL, endpoint, true);
					printf("%-20s      %5s",
						conversation_str,
						port_str);
					wmem_free(NULL, port_str);
				} else {
					printf("%-20s",
						conversation_str);
				}
				wmem_free(NULL, conversation_str);

				if (!prefs.conv_machine_readable) {
					char *rx_bytes, *tx_bytes, *total_bytes;
					rx_bytes = format_size(endpoint->rx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
					tx_bytes = format_size(endpoint->tx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
					total_bytes = format_size(endpoint->tx_bytes + endpoint->rx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
					printf("     %8" PRIu64 "   %-11s"
						"  %8" PRIu64 "      %-11s"
						"   %8" PRIu64 "      %-11s \n",
						endpoint->tx_frames+endpoint->rx_frames,
						total_bytes,
						endpoint->tx_frames, tx_bytes,
						endpoint->rx_frames, rx_bytes);
					wmem_free(NULL, rx_bytes);
					wmem_free(NULL, tx_bytes);
					wmem_free(NULL, total_bytes);
				} else {
					printf("     %8" PRIu64 "   %9" PRIu64
						"    %8" PRIu64 "      %9" PRIu64
						"     %8" PRIu64 "      %9" PRIu64 "  \n",
						endpoint->tx_frames+endpoint->rx_frames, endpoint->tx_bytes+endpoint->rx_bytes,
						endpoint->tx_frames, endpoint->tx_bytes,
						endpoint->rx_frames, endpoint->rx_bytes);
				}
			}
		}
		max_frames = last_frames;
	} while (last_frames);
	printf("================================================================================\n");
}

static void
endpoints_finish(void *arg)
{
	if (!arg)
		return;
	conv_hash_t *hash = (conv_hash_t*)arg;
	endpoints_t *iu = (endpoints_t *)hash->user_data;
	reset_endpoint_table_data(hash);
	if (iu) {
		g_free((char *)iu->filter);
		g_free(iu);
	}
}

void init_endpoints(struct register_ct *ct, const char *filter)
{
	endpoints_t *iu;
	GString *error_string;

	iu = g_new0(endpoints_t, 1);
	iu->type = proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(ct)));
	iu->filter = g_strdup(filter);
	iu->hash.user_data = iu;
	iu->table = conv_merge_add_table(&iu->hash, true);
	iu->packet_func = get_endpoint_packet_func(ct);

	error_string = register_tap_listener(proto_get_protocol_filter_name(get_conversation_proto_id(ct)), &iu->hash, filter, 0, NULL, conv_merge_needs_frames() ? endpoints_packet : iu->packet_func, endpoints_draw, endpoints_finish);
	if (error_string) {
		g_free(iu);
		cmdarg_err("Couldn't register endpoint tap: %s",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
