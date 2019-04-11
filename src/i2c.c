/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <libpdbg.h>
#include <inttypes.h>
#include <stdlib.h>

#include "main.h"
#include "optcmd.h"
#include "path.h"
#include "target.h"

static int geti2c(uint8_t addr, uint16_t size)
{
	uint8_t *data = NULL;
	struct pdbg_target *target, *selected = NULL;

	data = malloc(size);
	assert(data);

	for_each_path_target_class("i2c_bus", target) {
		if (pdbg_target_probe(target) != PDBG_TARGET_ENABLED)
			continue;
		selected = target;
		if (i2c_read(target, addr, size, data) == 0)
			break;
		break;
	}

	if (selected == NULL)
		return -1;
	printf("data read: 0x%016" PRIx64 "\n",  (uint64_t)*data);
	return 0;
}
OPTCMD_DEFINE_CMD_WITH_ARGS(geti2c, geti2c, (DATA8, DATA16));
