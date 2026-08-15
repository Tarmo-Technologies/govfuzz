/* SPDX-License-Identifier: Apache-2.0 */
#include "sqlite3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *sql=(char *)malloc(size+1); if(!sql)return 0; memcpy(sql,data,size); sql[size]=0;
  sqlite3 *db=NULL; if(sqlite3_open(":memory:",&db)==SQLITE_OK){const char *tail=sql; while(*tail){sqlite3_stmt *s=NULL; const char *next=NULL; if(sqlite3_prepare_v2(db,tail,-1,&s,&next)!=SQLITE_OK)break; while(s&&sqlite3_step(s)==SQLITE_ROW){} sqlite3_finalize(s); if(!next||next<=tail)break; tail=next;} sqlite3_close(db);} free(sql); return 0;
}
