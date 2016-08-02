/* $OpenBSD$ */

/*
 * Copyright (c) 2015 Philip Homburg <philip@f-src.phicoh.com>
 * Copyright (c) 2007 Simon Vallet / Genoscope <svallet@genoscope.cns.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#if !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_GETDNS)

#include <stdlib.h>
#include <string.h>

#include <getdns/getdns.h>

#include "getrrsetbyname.h"
#include "log.h"
#include "xmalloc.h"

#define malloc(x)	(xmalloc(x))
#define calloc(x, y)	(xcalloc((x),(y)))


int
getrrsetbyname(const char *hostname, unsigned int rdclass,
	       unsigned int rdtype, unsigned int flags,
	       struct rrsetinfo **res)
{
	int result, dnssec_status;
	getdns_return_t this_ret;  /* Holder for all function returns */
	uint32_t this_error;
	getdns_context *this_context = NULL;
	getdns_dict * this_extensions = NULL;
	getdns_dict * this_response = NULL;
	getdns_list *replies_tree_list;
	getdns_dict *reply_dict;
	getdns_list *answer_list;
	size_t num_answers, rec_count, ans_count;
	struct rrsetinfo *rrset = NULL;
	struct rdatainfo *rdata;

	/* don't allow flags yet, unimplemented */
	if (flags) {
		result = ERRSET_INVAL;
		goto done;
	}

	if (rdclass != ns_c_in)
	{
		/* We only support class IN */
		debug2("getdns: we only support class IN\n");
		result = ERRSET_FAIL;
		goto done;
	}

	/* Create the DNS context for this call */
	this_ret = getdns_context_create(&this_context, 1);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2("getdns: trying to create the context failed: %d\n",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	this_extensions = getdns_dict_create();
	this_ret = getdns_dict_set_int(this_extensions,
		"dnssec_return_status", GETDNS_EXTENSION_TRUE);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2("getdns: trying to set an extension for DNSSEC failed: %d", this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	/* Set up the getdns_sync_request call */
	this_ret = getdns_general_sync(this_context, hostname, rdtype,
		this_extensions, &this_response);
	if (this_ret == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		debug2("getdns: bad domain name was used: %s\n", hostname);
		result = ERRSET_FAIL;
		goto done;
	}

	/* Be sure the search returned something */
	this_ret = getdns_dict_get_int(this_response, "status", &this_error);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2("getdns: getdns_dict_get_int failed for 'status': %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	if (this_error != GETDNS_RESPSTATUS_GOOD)  // If the search didn't return "good"
	{
		debug2("getdns: the search had no results, and status %d",
			this_error);
		result = ERRSET_FAIL;
		goto done;
	}

	this_ret = getdns_dict_get_list(this_response, "replies_tree",
		&replies_tree_list);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2(
		"getdns: getdns_dict_get_list failed for 'replies_tree': %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	/* Assume one reply */
	this_ret = getdns_list_get_dict(replies_tree_list, 0, &reply_dict);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2("getdns: getdns_list_get_dict failed for '[0]': %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	this_ret = getdns_dict_get_int(reply_dict, "dnssec_status", &dnssec_status);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2(
		"getdns: getdns_dict_get_int failed for 'dnssec_status': %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	this_ret = getdns_dict_get_list(reply_dict, "answer",
		&answer_list);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2(
		"getdns: getdns_dict_get_list failed for 'answer': %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	this_ret = getdns_list_get_length(answer_list, &num_answers);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		debug2("getdns: getdns_list_get_length failed: %d",
			this_ret);
		result = ERRSET_FAIL;
		goto done;
	}

	/* initialize rrset */
	rrset = calloc(1, sizeof(struct rrsetinfo));
	if (rrset == NULL) {
		result = ERRSET_NOMEMORY;
		goto done;
	}
	rrset->rri_nrdatas = num_answers;
	if (!rrset->rri_nrdatas) {
		result = ERRSET_NODATA;
		goto done;
	}

	if (dnssec_status == GETDNS_DNSSEC_SECURE)
		rrset->rri_flags |= RRSET_VALIDATED;

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	   sizeof(struct rdatainfo));

	if (rrset->rri_rdatas == NULL) {
		result = ERRSET_NOMEMORY;
		goto done;
	}


	/* Go through each record */
	rec_count= 0;
	for ( ans_count = 0; ans_count < num_answers; ++ans_count )
	{
		getdns_dict * this_answer;
		getdns_dict *rdata_dict;
		getdns_bindata *this_rdata_data;
		int answer_type;

		this_ret = getdns_list_get_dict(answer_list, ans_count,
			&this_answer);
		if (this_ret != GETDNS_RETURN_GOOD)
		{
			debug2(
			"getdns: getdns_list_get_dict failed for '[%d]': %d",
				ans_count, this_ret);
			result = ERRSET_FAIL;
			goto done;
		}

		this_ret= getdns_dict_get_int(this_answer, "type",
			&answer_type);		
		if (this_ret != GETDNS_RETURN_GOOD)
		{
			debug2(
			"getdns: getdns_dict_get_int failed for 'type': %d",
				this_ret);
			result = ERRSET_FAIL;
			goto done;
		}

		if ((unsigned)answer_type != rdtype)
			continue;

		this_ret = getdns_dict_get_dict(this_answer, "rdata",
			&rdata_dict);
		if (this_ret != GETDNS_RETURN_GOOD)
		{
			debug2(
			"getdns: getdns_dict_get_dict failed for 'rdata': %d",
				this_ret);
			result = ERRSET_FAIL;
			goto done;
		}

		this_ret = getdns_dict_get_bindata(rdata_dict, "rdata_raw",
			&this_rdata_data); // Ignore any error
		if (this_ret != GETDNS_RETURN_GOOD)
		{
			debug2(
		"getdns: getdns_dict_get_bindata failed for 'rdata_raw': %d",
				this_ret);
			result = ERRSET_FAIL;
			goto done;
		}

		rdata = &rrset->rri_rdatas[rec_count];
		rdata->rdi_length = this_rdata_data->size;

		rdata->rdi_data = malloc(rdata->rdi_length);
		if (rdata->rdi_data == NULL) {
			result = ERRSET_NOMEMORY;
			goto done;
		}

		memcpy(rdata->rdi_data, this_rdata_data->data,
			rdata->rdi_length);

		rec_count++;
	}

	rrset->rri_nrdatas = rec_count;

	*res = rrset;
	rrset= NULL;
	result = ERRSET_SUCCESS;

done:
	getdns_dict_destroy(this_response); 
	getdns_dict_destroy(this_extensions);
	getdns_context_destroy(this_context);
	freerrset(rrset);

	return result;
}


void
freerrset(struct rrsetinfo *rrset)
{
	u_int16_t i;

	if (rrset == NULL)
		return;

	if (rrset->rri_rdatas) {
		for (i = 0; i < rrset->rri_nrdatas; i++) {
			if (rrset->rri_rdatas[i].rdi_data == NULL)
				break;
			free(rrset->rri_rdatas[i].rdi_data);
		}
		free(rrset->rri_rdatas);
	}

	if (rrset->rri_sigs) {
		for (i = 0; i < rrset->rri_nsigs; i++) {
			if (rrset->rri_sigs[i].rdi_data == NULL)
				break;
			free(rrset->rri_sigs[i].rdi_data);
		}
		free(rrset->rri_sigs);
	}

	if (rrset->rri_name)
		free(rrset->rri_name);
	free(rrset);
}


#endif /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
