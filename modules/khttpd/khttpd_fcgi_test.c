static void
khttpd_fcgi_check_loc_data_invariants
(struct khttpd_fcgi_location_data *loc_data)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	int n;

	mtx_assert(&loc_data->lock, MA_OWNED);

	n = 0;
	STAILQ_FOREACH(xchg_data, &loc_data->queue, link) {
		++n;

		/* waiting is true if a xchg_data is in 'queue' */
		KHTTPD_TEST_ASSERT(xchg_data->waiting);
	}

	/* loc_data->nwaiting is the number of elements in 'queue' */
	KHTTPD_TEST_ASSERT_OP("%d", loc_data->nwaiting, ==, n);
}

static void
khttpd_fcgi_check_invariants(void)
{
	struct khttpd_fcgi_conn *conn;
	int i, n;

	mtx_assert(&khttpd_fcgi_lock, MA_OWNED);

	/*
	 * Khttpd_fcgi_nconn_waiting is true only when khttpd_fcgi_exiting is
	 * true.
	 */
	KHTTPD_TEST_ASSERT(!khttpd_fcgi_nconn_waiting || khttpd_fcgi_exiting);

	n = 0;
	LIST_FOREACH(conn, &khttpd_fcgi_conns, allliste) {
		++n;

		/* free_on_unhold is true only when hold is true. */
		KHTTPD_TEST_ASSERT(!conn->free_on_unhold || conn->hold);
	}

	/* khttpd_fcgi_nconn is the number of elements in khttpd_fcgi_conns. */
	KHTTPD_TEST_ASSERT_OP("%d", n, ==, khttpd_fcgi_nconn);
}
