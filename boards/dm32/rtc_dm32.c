// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// DM-32UV: the SoC's real-time clock on its internal I2C2 (docs/spec/hardware-dm32.md 3.3), kept by the coin cell
// through power-off (hal_rtc.h). The clock counts seconds, minutes, hours and a 16-bit day number; RadioFoundry counts
// the days from 2026-01-01 (OTAR's epoch, otar.md 7). Every bus wait has a time limit: a clock that doesn't answer
// reads as none
#include <stdbool.h>
#include <stdint.h>
#include "hal_rtc.h"
#include "hal_time.h"
#include "platform.h"

#define I2C2_BASE		0x14080000u
#define IC_CON			REG32(I2C2_BASE + 0x00)
#define IC_TAR			REG32(I2C2_BASE + 0x04)
#define IC_DATA_CMD		REG32(I2C2_BASE + 0x10)
#define IC_FS_SCL_HCNT		REG32(I2C2_BASE + 0x1C)
#define IC_FS_SCL_LCNT		REG32(I2C2_BASE + 0x20)
#define IC_INTR_MASK		REG32(I2C2_BASE + 0x30)
#define IC_RX_TL		REG32(I2C2_BASE + 0x38)
#define IC_TX_TL		REG32(I2C2_BASE + 0x3C)
#define IC_CLR_INTR		REG32(I2C2_BASE + 0x40)
#define IC_ENABLE		REG32(I2C2_BASE + 0x6C)
#define IC_STATUS		REG32(I2C2_BASE + 0x70)
#define IC_ENABLE_STATUS	REG32(I2C2_BASE + 0x9C)
#define IC_START		REG32(I2C2_BASE + 0xA0)	// non-standard: starts the queued transfer
#define ST_ACTIVITY		0x01u
#define ST_TFE			0x04u	// transmit FIFO empty
#define ST_RFNE			0x08u	// receive FIFO not empty
#define DATA_READ		0x100u

#define RTC_ADDR		0x70u
#define R_SEC			0x00u	// .. 0x04: seconds, minutes, hours, day low, day high
#define R_LOAD_SEC		0x0Cu	// .. 0x10: the same, to load
#define R_CCR			0x11u
#define R_VSTAT			0x12u	// bit 0: the time loaded is valid
#define CCR_RUN			0x02u
#define CCR_LOAD		0x04u	// self clearing
#define EPOCH			1767225600	// 2026-01-01 00:00 UTC
#define DAY_S			86400

#define BUS_WAIT_US		3000u	// one register's transfer at fast mode is well under this
#define LOAD_WAIT_MS		50u

static bool ready;

static bool wait_status(uint32_t mask, uint32_t want)
{
	uint32_t t0 = hal_micros();
	while ((IC_STATUS & mask) != want)
		if ((uint32_t)(hal_micros() - t0) > BUS_WAIT_US)
			return false;
	return true;
}

static void bus_init(void)
{
	IC_ENABLE = 0;
	IC_CON = 0x65;
	IC_INTR_MASK = 0x40;
	IC_FS_SCL_HCNT = 0x61;
	IC_FS_SCL_LCNT = 0x68;
	IC_TX_TL = 6;
	IC_RX_TL = 6;
	ready = true;
}

static void open_bus(void)
{
	IC_ENABLE = 0;
	(void)IC_CLR_INTR;
	IC_TAR = RTC_ADDR;
	IC_ENABLE = 1;
}

static bool close_bus(void)
{
	IC_START = 0;
	IC_ENABLE = 0;
	uint32_t t0 = hal_micros();
	while (IC_ENABLE_STATUS & 1u)
		if ((uint32_t)(hal_micros() - t0) > BUS_WAIT_US)
			return false;
	return true;
}

static bool wr(uint8_t reg, uint8_t val)
{
	open_bus();
	IC_DATA_CMD = reg;
	IC_DATA_CMD = val;
	IC_START = 1;
	bool ok = wait_status(ST_TFE | ST_ACTIVITY, ST_TFE);
	return close_bus() && ok;
}

static bool rd(uint8_t reg, uint8_t *val)
{
	for (unsigned i = 0; i < 16u && (IC_STATUS & ST_RFNE); i++)
		(void)IC_DATA_CMD;	// whatever an earlier transfer left
	open_bus();
	IC_DATA_CMD = reg;
	IC_DATA_CMD = DATA_READ;
	IC_START = 1;
	bool ok = wait_status(ST_RFNE, ST_RFNE);
	if (ok)
		*val = (uint8_t)IC_DATA_CMD;
	return close_bus() && ok;
}

static bool rd_time(uint8_t t[5])
{
	for (uint8_t i = 0; i < 5u; i++)
		if (!rd((uint8_t)(R_SEC + i), &t[i]))
			return false;
	return true;
}

bool hal_rtc_get(int64_t *unix_s)
{
	if (!ready)
		bus_init();
	uint8_t v = 0, a[5], b[5];
	if (!rd(R_VSTAT, &v) || !(v & 1u))
		return false;
	// Two reads that agree: none taken across a carry
	bool same = false;
	for (unsigned tries = 0; tries < 3u && !same; tries++) {
		if (!rd_time(a) || !rd_time(b))
			return false;
		same = a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4];
	}
	uint8_t s = a[0] & 0x3Fu, m = a[1] & 0x3Fu, h = a[2] & 0x1Fu;
	if (!same || s > 59u || m > 59u || h > 23u)
		return false;
	uint32_t days = (uint32_t)a[3] | ((uint32_t)a[4] << 8);
	*unix_s = EPOCH + (int64_t)days * DAY_S + (int64_t)h * 3600 + (int64_t)m * 60 + s;
	return true;
}

bool hal_rtc_set(int64_t unix_s)
{
	if (unix_s < EPOCH || unix_s >= EPOCH + (int64_t)0xFFFF * DAY_S)
		return false;
	if (!ready)
		bus_init();
	int64_t t = unix_s - EPOCH;
	uint32_t days = (uint32_t)(t / DAY_S), sod = (uint32_t)(t % DAY_S);
	bool ok = wr(R_VSTAT, 0) && wr(R_LOAD_SEC, (uint8_t)(sod % 60u)) && wr(R_LOAD_SEC + 1u, (uint8_t)(sod / 60u % 60u)) &&
		  wr(R_LOAD_SEC + 2u, (uint8_t)(sod / 3600u)) && wr(R_LOAD_SEC + 3u, (uint8_t)days) &&
		  wr(R_LOAD_SEC + 4u, (uint8_t)(days >> 8)) && wr(R_CCR, CCR_RUN | CCR_LOAD);
	// The load bit clears once the clock took the time
	uint8_t ccr = CCR_LOAD;
	uint32_t t0 = hal_millis();
	while (ok && (ccr & CCR_LOAD) && (uint32_t)(hal_millis() - t0) < LOAD_WAIT_MS)
		ok = rd(R_CCR, &ccr);
	return ok && !(ccr & CCR_LOAD) && wr(R_VSTAT, 1);
}
