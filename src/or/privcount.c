/**
 * \file privcount.c
 * \brief Privacy-preserving data collection
 **/

#include "sys/socket.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "netdb.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"
#include "errno.h"
#include "arpa/inet.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitlist.h"
#include "connection_or.h"
#include "control.h"
#include "privcount.h"

int privcount_dns_resolved(edge_connection_t *exitconn, or_circuit_t *oncirc) {
    // rgj - we dont want to count dns for now
    return 0;

    if(!get_options()->EnablePrivCount || !oncirc || !oncirc->p_chan || !exitconn) {
        return 0;
    }

    /** sendBUff[512] is big enough since the domain is going to be 256 bytes,
    *   the channelID will be at most 20 bytes, the circuitID 10 bytes, and then
    *   the "a " and two spaces will take up 4 bytes.
    */
    char sendBuff[512];
    snprintf(sendBuff, 512, "a %" PRIu64 " %" PRIu32 " %s", oncirc->p_chan->global_identifier, oncirc->p_circ_id, exitconn->base_.address);
    return control_event_privcount(sendBuff, strlen(sendBuff));
}

int privcount_stream_data_xferred(edge_connection_t *conn, uint64_t amt, int outbound) {
    if(!get_options()->EnablePrivCount) {
        return 0;
    }
    if(!conn) {
        return 0;
    }
    if(conn->base_.type != CONN_TYPE_EXIT) {
        return 0;
    }

    /* if the circuit started here, this is our own stream and we can ignore it */
    circuit_t* circ = circuit_get_by_edge_conn(conn);
    or_circuit_t *orcirc = NULL;
    if(circ) {
        if(CIRCUIT_IS_ORIGIN(circ)) {
            return 0;
        }
        /* now we know its an or_circuit_t */
        orcirc = TO_OR_CIRCUIT(circ);
    }

    struct timeval now;
    tor_gettimeofday(&now);
    char sendBuff[512];

    /* ChanID, CircID, StreamID, BW, Direction, Time */
    snprintf(sendBuff, 512, "b %"PRIu64" %"PRIu32" %"PRIu16" %s %"PRIu64" %ld.%06ld",
            orcirc && orcirc->p_chan ? orcirc->p_chan->global_identifier : 0,
            orcirc ? orcirc->p_circ_id : 0,
            conn->stream_id,
            (outbound == 1) ? "outbound" : "inbound",
            amt,
            (long)now.tv_sec, (long)now.tv_usec);
    return control_event_privcount(sendBuff, strlen(sendBuff));
}

int privcount_stream_ended(edge_connection_t *conn) {
    if(!get_options()->EnablePrivCount) {
        return 0;
    }

    if(!conn) {
        return 0;
    }

    /* if the circuit started here, this is our own stream and we can ignore it */
    circuit_t* circ = circuit_get_by_edge_conn(conn);
    or_circuit_t *orcirc = NULL;
    if(circ) {
        if(CIRCUIT_IS_ORIGIN(circ)) {
            return 0;
        }
        /* now we know its an or_circuit_t */
        orcirc = TO_OR_CIRCUIT(circ);
    }

    /* to exclude hidden-service "server" circuits, use this */
    //CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose)

    /* only collect stream info from exits to legitimate client-bound destinations.
     * this means we wont get hidden-service related info */
    if(conn->base_.type != CONN_TYPE_EXIT) {
        return 0;
    }
    int is_dns = conn->is_dns_request; // means a dns lookup
    int is_dir = (conn->dirreq_id != 0 || conn->base_.port == 1) ? 1 : 0; // means a dir request
    //int is_dir = (conn->base_.type == CONN_TYPE_DIR) ? 1 : 0;

    struct timeval now;
    tor_gettimeofday(&now);
    char sendBuff[512];

    /* ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd, isDNS, isDir */
    snprintf(sendBuff, 512, "s %"PRIu64" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu64" %"PRIu64" %ld.%06ld %ld.%06ld %d %d",
            orcirc && orcirc->p_chan ? orcirc->p_chan->global_identifier : 0,
            orcirc ? orcirc->p_circ_id : 0,
            conn->stream_id, conn->base_.port,
            conn->privcount_n_read, conn->privcount_n_written,
            (long)conn->base_.timestamp_created_tv.tv_sec, (long)conn->base_.timestamp_created_tv.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            is_dns, is_dir);
    return control_event_privcount(sendBuff, strlen(sendBuff));
}

int privcount_circuit_ended(or_circuit_t *orcirc) {
    if(!get_options()->EnablePrivCount) {
        return 0;
    }
    if(!orcirc) {
        return 0;
    }
    if(orcirc->privcount_event_emitted) {
        return 0;
    }

    /* only collect circuit info from first hops on circuits that were actually used
     * we already know this is not an origin circ since we have a or_circuit_t struct */
    int prev_is_client = 0, prev_is_relay = 0;
    if(orcirc->p_chan) {
        if(connection_or_digest_is_known_relay(orcirc->p_chan->identity_digest)) {
            prev_is_relay = 1;
        } else if(orcirc->p_chan->is_client) {
            prev_is_client = 1;
        }
    }

    int next_is_client = 0, next_is_relay = 0;
    if(orcirc->base_.n_chan) {
        if(connection_or_digest_is_known_relay(orcirc->base_.n_chan->identity_digest)) {
            next_is_relay = 1;
        } else if(orcirc->base_.n_chan->is_client) {
            next_is_client = 1;
        }
    }

    orcirc->privcount_event_emitted = 1;

    struct timeval now;
    tor_gettimeofday(&now);
    char sendBuff[512];

    /* ChanID, CircID, nCellsIn, nCellsOut, ReadBWDNS, WriteBWDNS, ReadBWExit, WriteBWExit, TimeStart, TimeEnd, PrevIP, prevIsClient, prevIsRelay, NextIP, nextIsClient, nextIsRelay */
    snprintf(sendBuff, 512, "c %"PRIu64" %"PRIu32" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %ld.%06ld %ld.%06ld %s %d %d %s %d %d",
            orcirc->p_chan ? orcirc->p_chan->global_identifier : 0, orcirc->p_circ_id,
            orcirc->privcount_n_cells_in, orcirc->privcount_n_cells_out,
            orcirc->privcount_n_read_dns, orcirc->privcount_n_written_dns,
            orcirc->privcount_n_read_exit, orcirc->privcount_n_written_exit,
            (long)orcirc->base_.timestamp_created.tv_sec, (long)orcirc->base_.timestamp_created.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            orcirc->p_chan ? channel_get_actual_remote_address(orcirc->p_chan) : "0.0.0.0",
            prev_is_client, prev_is_relay,
            orcirc->base_.n_chan ? channel_get_actual_remote_address(orcirc->base_.n_chan) : "0.0.0.0",
            next_is_client, next_is_relay);
    return control_event_privcount(sendBuff, strlen(sendBuff));
}

int privcount_connection_ended(or_connection_t *orconn) {
    if(!get_options()->EnablePrivCount) {
        return 0;
    }
    if(!orconn) {
        return 0;
    }

    channel_t* p_chan = (channel_t*)orconn->chan;

    int is_client = 0, is_relay = 0;
    if(p_chan) {
        if(connection_or_digest_is_known_relay(p_chan->identity_digest)) {
            is_relay = 1;
        } else if(p_chan->is_client) {
            is_client = 1;
        }
    }

    struct timeval now;
    tor_gettimeofday(&now);
    char sendBuff[512];

    /* ChanID, TimeStart, TimeEnd, IP, isClient, isRelay */
    snprintf(sendBuff, 512, "t %"PRIu64" %ld.%06ld %ld.%06ld %s %d %d",
            p_chan ? p_chan->global_identifier : 0,
            (long)orconn->base_.timestamp_created_tv.tv_sec, (long)orconn->base_.timestamp_created_tv.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            p_chan ? channel_get_actual_remote_address(p_chan) : "0.0.0.0",
            is_client, is_relay);
    return control_event_privcount(sendBuff, strlen(sendBuff));
}
