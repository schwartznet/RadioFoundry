// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * Auto DMR ID's formula (core/support/auto_dmr_id.c, docs/spec/auto-dmr-id.md) against tests/vectors/auto-dmr-id.txt,
 * the vectors tools/dmrid_from_uid.py --self-test checks too (computed with Python hashlib apart from this code), so
 * the radio and the PC helper can't drift apart. Also: every candidate stays in BASE..BASE + SPAN - 1, candidates differ
 *
 *   make -C tests/host run-auto-dmr-id
 */
#include <stdio.h>
#include <string.h>
#include "support/auto_dmr_id.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static bool hex12(const char *s, uint8_t out[AUTO_DMR_ID_UID_LEN])
{
	if (strlen(s) != 24)
		return false;
	for (unsigned i = 0; i < AUTO_DMR_ID_UID_LEN; i++) {
		unsigned v;
		if (sscanf(&s[2 * i], "%2x", &v) != 1)
			return false;
		out[i] = (uint8_t)v;
	}
	return true;
}

int main(void)
{
	FILE *f = fopen("../vectors/auto-dmr-id.txt", "r");
	CHECK(f != NULL);
	int vectors = 0;
	char line[160];
	while (f != NULL && fgets(line, sizeof line, f) != NULL) {
		if (line[0] == '#' || line[0] == '\n')
			continue;
		char uidtext[32];
		unsigned k;
		unsigned long base, span, want;
		uint8_t uid[AUTO_DMR_ID_UID_LEN];
		if (sscanf(line, "%31s %u %lu %lu %lu", uidtext, &k, &base, &span, &want) != 5)
			continue;
		CHECK(hex12(uidtext, uid));
		uint32_t got = auto_dmr_id(uid, (uint8_t)k, (uint32_t)base, (uint32_t)span);
		if (got != want)
			printf("FAIL %s candidate %u: %u, want %lu\n", uidtext, k, (unsigned)got, want);
		CHECK(got == want);
		vectors++;
	}
	if (f != NULL)
		fclose(f);
	CHECK(vectors >= 6);

	// The real radio's UID (rfoundry_debug.py chip): 4678512 with the default range
	uint8_t uid[AUTO_DMR_ID_UID_LEN];
	CHECK(hex12("401065E42855394B68455CAF", uid));
	CHECK(auto_dmr_id(uid, 0, 4670000, 10000) == 4678512);
	// In range for every candidate; the next candidates differ from the first
	for (unsigned k = 0; k < 256; k++) {
		uint32_t id = auto_dmr_id(uid, (uint8_t)k, 4670000, 10000);
		CHECK(id >= 4670000 && id <= 4679999);
	}
	CHECK(auto_dmr_id(uid, 1, 4670000, 10000) != auto_dmr_id(uid, 0, 4670000, 10000));
	CHECK(auto_dmr_id(uid, 0, 4670000, 0) == 0);

	printf("# autoDmrIdTest: %d checks, %s\n", checks, failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
