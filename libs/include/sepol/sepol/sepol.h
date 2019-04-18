#ifndef _SEPOL_H_
#define _SEPOL_H_

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "user_record.h"
#include "context_record.h"
#include "iface_record.h"
#include "ibpkey_record.h"
#include "ibendport_record.h"
#include "port_record.h"
#include "boolean_record.h"
#include "node_record.h"

#include "booleans.h"
#include "interfaces.h"
#include "ibpkeys.h"
#include "ibendports.h"
#include "ports.h"
#include "nodes.h"
#include "users.h"
#include "handle.h"
#include "debug.h"
#include "policydb.h"
#include "module.h"
#include "context.h"

/* Set internal policydb from a file for subsequent service calls. */
extern int sepol_set_policydb_from_file(FILE * fp);

#ifdef __cplusplus
}
#endif

#endif
