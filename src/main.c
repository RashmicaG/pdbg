/* Copyright 2016 IBM Corp.
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
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <inttypes.h>

#include <ccan/array_size/array_size.h>

#include <config.h>

#include <libpdbg.h>
#include <target.h>

#include "main.h"
#include "cfam.h"
#include "scom.h"
#include "reg.h"
#include "ring.h"
#include "mem.h"
#include "thread.h"
#include "htm.h"
#include "options.h"
#include "pdbgproxy.h"

#define PR_ERROR(x, args...) \
	pdbg_log(PDBG_ERROR, x, ##args)

#include "fake.dt.h"

#ifdef TARGET_ARM
#include "p8-i2c.dt.h"
#include "p8-fsi.dt.h"
#include "p9w-fsi.dt.h"
#include "p9r-fsi.dt.h"
#include "p9z-fsi.dt.h"
#include "p9-kernel.dt.h"
#endif

#ifdef TARGET_PPC
#include "p8-host.dt.h"
#include "p9-host.dt.h"
#endif

#define THREADS_PER_CORE	8

static enum backend backend = KERNEL;

static char const *device_node;
static int i2c_addr = 0x50;

#define MAX_PROCESSORS 64
#define MAX_CHIPS 24
#define MAX_THREADS THREADS_PER_CORE

static int **processorsel[MAX_PROCESSORS];
static int *chipsel[MAX_PROCESSORS][MAX_CHIPS];
static int threadsel[MAX_PROCESSORS][MAX_CHIPS][MAX_THREADS];

static int handle_probe(int optind, int argc, char *argv[]);
static int handle_release(int optind, int argc, char *argv[]);

struct action {
	const char *name;
	const char *args;
	const char *desc;
	int (*fn)(int, int, char **);
};

static struct action actions[] = {
	{ "getgpr",  "<gpr>", "Read General Purpose Register (GPR)", &handle_gpr },
	{ "putgpr",  "<gpr> <value>", "Write General Purpose Register (GPR)", &handle_gpr },
	{ "getnia",  "", "Get Next Instruction Address (NIA)", &handle_nia },
	{ "putnia",  "<value>", "Write Next Instrution Address (NIA)", &handle_nia },
	{ "getspr",  "<spr>", "Get Special Purpose Register (SPR)", &handle_spr },
	{ "putspr",  "<spr> <value>", "Write Special Purpose Register (SPR)", &handle_spr },
	{ "getmsr",  "", "Get Machine State Register (MSR)", &handle_msr },
	{ "putmsr",  "<value>", "Write Machine State Register (MSR)", &handle_msr },
	{ "getcr",  "", "Get Condition Register (CR)", &handle_cr },
	{ "putcr",  "<value>", "Write Condition Register (CR)", &handle_cr },
	{ "getxer",  "", "Get Fixed Point Exception Register (XER)", &handle_xer },
	{ "putxer",  "<value>", "Write Fixed Point Exception Register (XER)", &handle_xer },
	{ "getring", "<addr> <len>", "Read a ring. Length must be correct", &handle_getring },
	{ "start",   "", "Start thread", &thread_start },
	{ "step",    "<count>", "Set a thread <count> instructions", &thread_step },
	{ "stop",    "", "Stop thread", &thread_stop },
	{ "htm", "core|nest start|stop|status|reset|dump|trace|analyse", "Hardware Trace Macro", &run_htm },
	{ "release", "", "Should be called after pdbg work is finished, to release special wakeups and other resources.", &handle_release},
	{ "probe", "", "", &handle_probe },
	{ "getcfam", "<address>", "Read system cfam", &handle_cfams },
	{ "putcfam", "<address> <value> [<mask>]", "Write system cfam", &handle_cfams },
	{ "getscom", "<address>", "Read system scom", &handle_scoms },
	{ "putscom", "<address> <value> [<mask>]", "Write system scom", &handle_scoms },
	{ "getmem",  "<address> <count>", "Read system memory", &handle_mem },
	{ "putmem",  "<address>", "Write to system memory", &handle_mem },
	{ "threadstatus", "", "Print the status of a thread", &thread_status_print },
	{ "sreset",  "", "Reset", &thread_sreset },
	{ "regs",  "", "State", &thread_state },
	{ "gdbserver", "", "", &handle_gdb },
};


static void print_usage(char *pname)
{
	int i;

	printf("Usage: %s [options] command ...\n\n", pname);
	printf(" Options:\n");
	printf("\t-p, --processor=<0-%d>|<range>|<list>\n", MAX_PROCESSORS-1);
	printf("\t-c, --chip=<0-%d>|<range>|<list>\n", MAX_CHIPS-1);
	printf("\t-t, --thread=<0-%d>|<range>|<list>\n", MAX_THREADS-1);
	printf("\t-a, --all\n");
	printf("\t\tRun command on all possible processors/chips/threads (default)\n");
	printf("\t-b, --backend=backend\n");
	printf("\t\tfsi:\tAn experimental backend that uses\n");
	printf("\t\t\tbit-banging to access the host processor\n");
	printf("\t\t\tvia the FSI bus.\n");
	printf("\t\ti2c:\tThe P8 only backend which goes via I2C.\n");
	printf("\t\thost:\tUse the debugfs xscom nodes.\n");
	printf("\t\tkernel:\tThe default backend which goes the kernel FSI driver.\n");
	printf("\t-d, --device=backend device\n");
	printf("\t\tFor I2C the device node used by the backend to access the bus.\n");
	printf("\t\tFor FSI the system board type, one of p8 or p9w\n");
	printf("\t\tDefaults to /dev/i2c4 for I2C\n");
	printf("\t-s, --slave-address=backend device address\n");
	printf("\t\tDevice slave address to use for the backend. Not used by FSI\n");
	printf("\t\tand defaults to 0x50 for I2C\n");
	printf("\t-D, --debug=<debug level>\n");
	printf("\t\t0:error (default) 1:warning 2:notice 3:info 4:debug\n");
	printf("\t-V, --version\n");
	printf("\t-h, --help\n");
	printf("\n");
	printf(" Commands:\n");
	for (i = 0; i < ARRAY_SIZE(actions); i++)
		printf("  %-15s %-27s  %s\n", actions[i].name, actions[i].args, actions[i].desc);
}

/* Parse argument of the form 0-5,7,9-11,15,17 */
static bool parse_list(const char *arg, int max, int *list, int *count)
{
	char str[strlen(arg)+1];
	char *tok, *tmp, *saveptr = NULL;
	int i;

	assert(max < INT_MAX);

	strcpy(str, arg);

	for (i = 0; i < max; i++) {
		list[i] = 0;
	}

	tmp = str;
	while ((tok = strtok_r(tmp, ",", &saveptr)) != NULL) {
		char *a, *b, *endptr, *saveptr2 = NULL;
		unsigned long int from, to;

		a = strtok_r(tok, "-", &saveptr2);
		if (a == NULL) {
			return false;
		} else {
			endptr = NULL;
			from = strtoul(a, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, "Invalid value %s\n", a);
				return false;
			}
			if (from >= max) {
				fprintf(stderr, "Value %s larger than max %d\n", a, max-1);
				return false;
			}
		}

		b = strtok_r(NULL, "-", &saveptr2);
		if (b == NULL) {
			to = from;
		} else {
			endptr = NULL;
			to = strtoul(b, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, "Invalid value %s\n", b);
				return false;
			}
			if (to >= max) {
				fprintf(stderr, "Value %s larger than max %d\n", b, max-1);
				return false;
			}
		}

		if (from > to) {
			fprintf(stderr, "Invalid range %s-%s\n", a, b);
			return false;
		}

		for (i = from; i <= to; i++)
			list[i] = 1;

		tmp = NULL;
	};

	if (count != NULL) {
		int n = 0;

		for (i = 0; i < max; i++) {
			if (list[i] == 1)
				n++;
		}

		*count = n;
	}

	return true;
}

static bool parse_options(int argc, char *argv[])
{
	int c;
	bool opt_error = false;
	int p_list[MAX_PROCESSORS];
	int c_list[MAX_CHIPS];
	int t_list[MAX_THREADS];
	int p_count = 0, c_count = 0, t_count = 0;
	int i, j, k;
	struct option long_opts[] = {
		{"all",			no_argument,		NULL,	'a'},
		{"backend",		required_argument,	NULL,	'b'},
		{"chip",		required_argument,	NULL,	'c'},
		{"device",		required_argument,	NULL,	'd'},
		{"help",		no_argument,		NULL,	'h'},
		{"processor",		required_argument,	NULL,	'p'},
		{"slave-address",	required_argument,	NULL,	's'},
		{"thread",		required_argument,	NULL,	't'},
		{"debug",		required_argument,	NULL,	'D'},
		{"version",		no_argument,		NULL,	'V'},
		{NULL,			0,			NULL,     0}
	};
	char *endptr;

	do {
		c = getopt_long(argc, argv, "+ab:c:d:hp:s:t:D:V", long_opts, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'a':
			if (p_count == 0) {
				p_count = MAX_PROCESSORS;
				for (i = 0; i < MAX_PROCESSORS; i++)
					p_list[i] = 1;
			}

			if (c_count == 0) {
				c_count = MAX_CHIPS;
				for (i = 0; i < MAX_CHIPS; i++)
					c_list[i] = 1;
			}

			if (t_count == 0) {
				t_count = MAX_THREADS;
				for (i = 0; i < MAX_THREADS; i++)
					t_list[i] = 1;
			}
			break;

		case 'p':
			if (!parse_list(optarg, MAX_PROCESSORS, p_list, &p_count)) {
				fprintf(stderr, "Failed to parse '-p %s'\n", optarg);
				opt_error = true;
			}
			break;

		case 'c':
			if (!parse_list(optarg, MAX_CHIPS, c_list, &c_count)) {
				fprintf(stderr, "Failed to parse '-c %s'\n", optarg);
				opt_error = true;
			}
			break;

		case 't':
			if (!parse_list(optarg, MAX_THREADS, t_list, &t_count)) {
				fprintf(stderr, "Failed to parse '-t %s'\n", optarg);
				opt_error = true;
			}
			break;

		case 'b':
			if (strcmp(optarg, "fsi") == 0) {
				backend = FSI;
				device_node = "p9w";
			} else if (strcmp(optarg, "i2c") == 0) {
				backend = I2C;
			} else if (strcmp(optarg, "kernel") == 0) {
				backend = KERNEL;
				/* TODO: use device node to point at a slave
				 * other than the first? */
			} else if (strcmp(optarg, "fake") == 0) {
				backend = FAKE;
			} else if (strcmp(optarg, "host") == 0) {
				backend = HOST;
			} else {
				fprintf(stderr, "Invalid backend '%s'\n", optarg);
				opt_error = true;
			}
			break;

		case 'd':
			device_node = optarg;
			break;

		case 's':
			errno = 0;
			i2c_addr = strtoull(optarg, &endptr, 0);
			opt_error = (errno || *endptr != '\0');
			if (opt_error)
				fprintf(stderr, "Invalid slave address '%s'\n", optarg);
			break;

		case 'D':
			pdbg_set_loglevel(atoi(optarg));
			break;

		case 'V':
			printf("%s (commit %s)\n", PACKAGE_STRING, GIT_SHA1);
			exit(0);
			break;

		case '?':
		case 'h':
			opt_error = true;
			print_usage(basename(argv[0]));
			break;
		}
	} while (c != EOF && !opt_error);

	if (opt_error) {
		return false;
	}

	if ((c_count > 0 || t_count > 0) && p_count == 0) {
		fprintf(stderr, "No processor(s) selected\n");
		fprintf(stderr, "Use -p or -a to select processor(s)\n");
		return false;
	}

	if (t_count > 0 && c_count == 0)  {
		fprintf(stderr, "No chip(s) selected\n");
		fprintf(stderr, "Use -c or -a to select chip(s)\n");
		return false;
	}

	for (i = 0; i < MAX_PROCESSORS; i++) {
		if (p_list[i] == 0)
			continue;

		processorsel[i] = &chipsel[i][0];

		for (j = 0; j < MAX_CHIPS; j++) {
			if (c_list[j] == 0)
				continue;

			chipsel[i][j] = &threadsel[i][j][0];

			for (k = 0; k < MAX_THREADS; k++) {
				if (t_list[k] == 0)
					continue;

				threadsel[i][j][k] = 1;
			}
		}
	}

	return true;
}

void target_select(struct pdbg_target *target)
{
	/* We abuse the private data pointer atm to indicate the target is
	 * selected */
	pdbg_target_priv_set(target, (void *) 1);
}

void target_unselect(struct pdbg_target *target)
{
	pdbg_target_priv_set(target, NULL);
}

bool target_selected(struct pdbg_target *target)
{
	return (bool) pdbg_target_priv(target);
}

/* Returns the sum of return codes. This can be used to count how many targets the callback was run on. */
int for_each_child_target(char *class, struct pdbg_target *parent,
				 int (*cb)(struct pdbg_target *, uint32_t, uint64_t *, uint64_t *),
				 uint64_t *arg1, uint64_t *arg2)
{
	int rc = 0;
	struct pdbg_target *target;
	uint32_t index;
	enum pdbg_target_status status;

	pdbg_for_each_target(class, parent, target) {
		if (!target_selected(target))
			continue;

		index = pdbg_target_index(target);
		assert(index != -1);
		pdbg_target_probe(target);
		status = pdbg_target_status(target);
		if (status != PDBG_TARGET_ENABLED)
			continue;

		rc += cb(target, index, arg1, arg2);
	}

	return rc;
}

int for_each_target(char *class, int (*cb)(struct pdbg_target *, uint32_t, uint64_t *, uint64_t *), uint64_t *arg1, uint64_t *arg2)
{
	struct pdbg_target *target;
	uint32_t index;
	enum pdbg_target_status status;
	int rc = 0;

	pdbg_for_each_class_target(class, target) {
		if (!target_selected(target))
			continue;

		index = pdbg_target_index(target);
		assert(index != -1);
		pdbg_target_probe(target);
		status = pdbg_target_status(target);
		if (status != PDBG_TARGET_ENABLED)
			continue;

		rc += cb(target, index, arg1, arg2);
	}

	return rc;
}

void for_each_target_release(char *class)
{
	struct pdbg_target *target;

	pdbg_for_each_class_target(class, target) {
		if (!target_selected(target))
			continue;

		pdbg_target_release(target);
	}
}

static int target_selection(void)
{
	struct pdbg_target *fsi, *pib, *chip, *thread;

	switch (backend) {
#ifdef TARGET_ARM
	case I2C:
		pdbg_targets_init(&_binary_p8_i2c_dtb_o_start);
		break;

	case FSI:
		if (device_node == NULL) {
			PR_ERROR("FSI backend requires a device type\n");
			return -1;
		}
		if (!strcmp(device_node, "p8"))
			pdbg_targets_init(&_binary_p8_fsi_dtb_o_start);
		else if (!strcmp(device_node, "p9w"))
			pdbg_targets_init(&_binary_p9w_fsi_dtb_o_start);
		else if (!strcmp(device_node, "p9r"))
			pdbg_targets_init(&_binary_p9r_fsi_dtb_o_start);
		else if (!strcmp(device_node, "p9z"))
			pdbg_targets_init(&_binary_p9z_fsi_dtb_o_start);
		else {
			PR_ERROR("Invalid device type specified\n");
			return -1;
		}
		break;

	case KERNEL:
		pdbg_targets_init(&_binary_p9_kernel_dtb_o_start);
		break;

#endif

#ifdef TARGET_PPC
	case HOST:
		if (device_node == NULL) {
			PR_ERROR("Host backend requires a device type\n");
			return -1;
		}
		if (!strcmp(device_node, "p8"))
			pdbg_targets_init(&_binary_p8_host_dtb_o_start);
		else if (!strcmp(device_node, "p9"))
			pdbg_targets_init(&_binary_p9_host_dtb_o_start);
		else {
			PR_ERROR("Unsupported device type for host backend\n");
			return -1;
		}
		break;
#endif

	case FAKE:
		pdbg_targets_init(&_binary_fake_dtb_o_start);
		break;

	default:
		PR_ERROR("Invalid backend specified\n");
		return -1;
	}

	/* At this point we should have a device-tree loaded. We want
	 * to walk the tree and disabled nodes we don't care about
	 * prior to probing. */
	pdbg_for_each_class_target("pib", pib) {
		int proc_index = pdbg_target_index(pib);

		if (backend == I2C && device_node)
			pdbg_set_target_property(pib, "bus", device_node, strlen(device_node) + 1);

		if (processorsel[proc_index]) {
			target_select(pib);
			pdbg_for_each_target("core", pib, chip) {
				int chip_index = pdbg_target_index(chip);
				if (pdbg_parent_index(chip, "pib") != proc_index)
					continue;

				if (chipsel[proc_index][chip_index]) {
					target_select(chip);
					pdbg_for_each_target("thread", chip, thread) {
						int thread_index = pdbg_target_index(thread);
						if (threadsel[proc_index][chip_index][thread_index])
							target_select(thread);
						else
							target_unselect(thread);
					}
				} else
					target_unselect(chip);
			}

			/* This is kinda broken as we're overloading what '-c'
			 * means - it's now up to each command to select targets
			 * based on core/chiplet. We really need a better
			 * solution to target selection. */
			pdbg_for_each_target("chiplet", pib, chip) {
				int chip_index = pdbg_target_index(chip);
				if (chipsel[proc_index][chip_index]) {
					target_select(chip);
				} else
					target_unselect(chip);
			}
		} else
			target_unselect(pib);
	}

	pdbg_for_each_class_target("fsi", fsi) {
		int index = pdbg_target_index(fsi);
		if (processorsel[index])
			target_select(fsi);
		else
			target_unselect(fsi);
	}

	return 0;
}

static void release_target(struct pdbg_target *target)
{
	struct pdbg_target *child;

	/* !selected targets may get selected in other ways */

	/* Does this target actually exist? */
	if ((pdbg_target_status(target) != PDBG_TARGET_ENABLED) &&
	    (pdbg_target_status(target) != PDBG_TARGET_PENDING_RELEASE))
		return;

	pdbg_for_each_child_target(target, child)
		release_target(child);

	pdbg_target_release(target);
}

static void do_release(void)
{
	struct pdbg_target_class *target_class;

	for_each_target_class(target_class) {
		struct pdbg_target *target;

		pdbg_for_each_class_target(target_class->name, target)
			release_target(target);
	}
}

void print_target(struct pdbg_target *target, int level)
{
	int i;
	struct pdbg_target *next;
	enum pdbg_target_status status;

	/* Did we want to probe this target? */
	if (!target_selected(target))
		return;

	pdbg_target_probe(target);

	/* Does this target actually exist? */
	status = pdbg_target_status(target);
	if (status != PDBG_TARGET_ENABLED)
		return;

	for (i = 0; i < level; i++)
		printf("    ");

	if (target) {
		char c = 0;
		if (!strcmp(pdbg_target_class_name(target), "pib"))
			c = 'p';
		else if (!strcmp(pdbg_target_class_name(target), "core"))
			c = 'c';
		else if (!strcmp(pdbg_target_class_name(target), "thread"))
			c = 't';

		if (c)
			printf("%c%d: %s\n", c, pdbg_target_index(target), pdbg_target_name(target));
		else
			printf("%s\n", pdbg_target_name(target));
	}

	pdbg_for_each_child_target(target, next) {
		print_target(next, level + 1);
	}
}

static int handle_probe(int optind, int argc, char *argv[])
{
	struct pdbg_target *target;

	pdbg_for_each_class_target("pib", target)
		print_target(target, 0);

	printf("\nNote that only selected targets will be shown above. If none are shown\n"
			"try adding '-a' to select all targets\n");

	return 1;
}

/*
 * Release handler.
 */
static void atexit_release(void)
{
	do_release();
}

static int handle_release(int optind, int argc, char *argv[])
{
	do_release();

	return 1;
}

int main(int argc, char *argv[])
{
	int i, rc = 0;

	backend = default_backend();
	device_node = default_target(backend);

	if (!parse_options(argc, argv))
		return 1;

	if (!backend_is_possible(backend)) {
		fprintf(stderr, "Backend not possible\nUse: ");
		print_backends(stderr);
		return 1;
	}

	if (!target_is_possible(backend, device_node)) {
		fprintf(stderr, "Target %s not possible\n",
			device_node ? device_node : "(none)");
		print_targets(stderr);
		return 1;
	}

	if (optind >= argc) {
		print_usage(basename(argv[0]));
		return 1;
	}

	/* Disable unselected targets */
	if (target_selection())
		return 1;

	atexit(atexit_release);

	for (i = 0; i < ARRAY_SIZE(actions); i++) {
		if (strcmp(argv[optind], actions[i].name) == 0) {
			rc = actions[i].fn(optind, argc, argv);
			goto found_action;
		}
	}

	PR_ERROR("Unsupported command: %s\n", argv[optind]);
	return 1;

found_action:
	if (rc > 0)
		return 0;

	printf("No valid targets found or specified. Try adding -p/-c/-t options to specify a target.\n");
	printf("Alternatively run '%s -a probe' to get a list of all valid targets\n",
	       basename(argv[0]));
	return 1;
}
