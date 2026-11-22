// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// Radio silence's flag (silence.h): here and not in the radio core, so the services that read it link without it
#include "radio/silence.h"

#if CONFIG_RADIO_SILENCE
volatile bool radio_silence_flag;
#endif
