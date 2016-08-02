#ifndef TOR_PRIVCOUNT_H
#define TOR_PRIVCOUNT_H

#include "or.h"
#include "config.h"

int privcount_dns_resolved(edge_connection_t *exitconn, or_circuit_t *oncirc);
int privcount_stream_data_xferred(edge_connection_t *conn, uint64_t amt, int outbound);
int privcount_stream_ended(edge_connection_t *conn);
int privcount_circuit_ended(or_circuit_t *orcirc);
int privcount_connection_ended(or_connection_t *orconn);

#endif /* !defined(TOR_PRIVCOUNT_H) */
